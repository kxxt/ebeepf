//! Classic traffic-control eBPF classifier management through rtnetlink.
//!
//! For kernels and deployments using link-based TCX, prefer
//! [`crate::Program::attach_tcx`]. This module manages the persistent `clsact`
//! qdisc and classic direct-action BPF filters.

use std::io;
use std::os::fd::AsRawFd;

use crate::netlink::{self, Request};
use crate::{Error, Program, Result};

const RTM_NEW_QDISC: u16 = 36;
const RTM_DELETE_QDISC: u16 = 37;
const RTM_NEW_FILTER: u16 = 44;
const RTM_DELETE_FILTER: u16 = 45;
const RTM_GET_FILTER: u16 = 46;

const TCA_KIND: u16 = 1;
const TCA_OPTIONS: u16 = 2;
const TCA_BPF_FD: u16 = 6;
const TCA_BPF_NAME: u16 = 7;
const TCA_BPF_FLAGS: u16 = 8;
const TCA_BPF_ID: u16 = 11;
const TCA_BPF_FLAG_DIRECT_ACTION: u32 = 1;

const TC_HANDLE_MAJOR_MASK: u32 = 0xffff_0000;
const TC_HANDLE_CLSACT: u32 = 0xffff_fff1;
const TC_HANDLE_MIN_INGRESS: u32 = 0xfff2;
const TC_HANDLE_MIN_EGRESS: u32 = 0xfff3;
const ETHERNET_PROTOCOL_ALL: u16 = 3;

/// Location at which a classic traffic-control classifier is attached.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum TcAttachPoint {
    /// The ingress side of a `clsact` qdisc.
    Ingress,
    /// The egress side of a `clsact` qdisc.
    Egress,
    /// An explicitly supplied traffic-control parent handle.
    Custom(u32),
}

impl TcAttachPoint {
    fn parent(self) -> Result<u32> {
        match self {
            Self::Ingress => Ok(make_handle(TC_HANDLE_CLSACT, TC_HANDLE_MIN_INGRESS)),
            Self::Egress => Ok(make_handle(TC_HANDLE_CLSACT, TC_HANDLE_MIN_EGRESS)),
            Self::Custom(0) => Err(Error::InvalidObject(
                "a custom traffic-control parent cannot be zero".into(),
            )),
            Self::Custom(parent) => Ok(parent),
        }
    }
}

/// Requested identity and update behavior for a classic TC filter.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TcAttachOptions {
    /// Requested filter handle, or zero for kernel allocation.
    pub handle: u32,
    /// Requested filter priority, or zero for kernel allocation.
    pub priority: u16,
    /// Replace an existing filter with this identity.
    pub replace: bool,
}

impl TcAttachOptions {
    /// Creates options which let the kernel allocate identity fields.
    pub const fn new() -> Self {
        Self {
            handle: 0,
            priority: 0,
            replace: false,
        }
    }

    /// Requests a particular handle and priority.
    pub const fn with_identity(mut self, handle: u32, priority: u16) -> Self {
        self.handle = handle;
        self.priority = priority;
        self
    }

    /// Enables atomic replacement of an existing classifier.
    pub const fn replacing(mut self) -> Self {
        self.replace = true;
        self
    }
}

/// Stable identity of one classic traffic-control filter.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TcFilterId {
    /// Traffic-control filter handle.
    pub handle: u32,
    /// Traffic-control filter priority.
    pub priority: u16,
}

impl TcFilterId {
    /// Creates a validated nonzero filter identity.
    pub fn new(handle: u32, priority: u16) -> Result<Self> {
        if handle == 0 || priority == 0 {
            return Err(Error::InvalidObject(
                "traffic-control filter handle and priority must be nonzero".into(),
            ));
        }
        Ok(Self { handle, priority })
    }
}

/// Kernel information for an attached classic TC filter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcFilterInfo {
    /// Filter identity used for query and removal.
    pub identity: TcFilterId,
    /// Kernel ID of the attached eBPF program.
    pub program_id: u32,
}

/// One interface and attachment point used for classic TC operations.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TcHook {
    interface_index: u32,
    attach_point: TcAttachPoint,
}

impl TcHook {
    /// Creates a hook descriptor without changing kernel state.
    pub fn new(interface_index: u32, attach_point: TcAttachPoint) -> Result<Self> {
        validate_interface_index(interface_index)?;
        attach_point.parent()?;
        Ok(Self {
            interface_index,
            attach_point,
        })
    }

    /// Returns the selected interface index.
    pub const fn interface_index(self) -> u32 {
        self.interface_index
    }

    /// Returns the selected traffic-control attachment point.
    pub const fn attach_point(self) -> TcAttachPoint {
        self.attach_point
    }

    /// Creates the interface's shared `clsact` qdisc.
    ///
    /// Ingress and egress use the same qdisc; callers should create it once.
    pub fn create_clsact(&self) -> Result<()> {
        if matches!(self.attach_point, TcAttachPoint::Custom(_)) {
            return Err(Error::Unsupported(
                "custom traffic-control parents do not imply a clsact qdisc".into(),
            ));
        }
        modify_clsact(self.interface_index, RTM_NEW_QDISC)
            .map_err(|source| Error::system("create clsact qdisc", source))
    }

    /// Removes the shared `clsact` qdisc and all of its filters.
    pub fn destroy_clsact(&self) -> Result<()> {
        if matches!(self.attach_point, TcAttachPoint::Custom(_)) {
            return Err(Error::Unsupported(
                "custom traffic-control parents do not imply a clsact qdisc".into(),
            ));
        }
        modify_clsact(self.interface_index, RTM_DELETE_QDISC)
            .map_err(|source| Error::system("destroy clsact qdisc", source))
    }

    /// Attaches a direct-action BPF classifier.
    ///
    /// The returned owner removes the filter on drop. Call
    /// [`TcFilter::persist`] when persistent kernel state is intentional.
    pub fn attach(&self, program: &Program, options: TcAttachOptions) -> Result<TcFilter> {
        let program_info = program.info()?;
        let info = attach_filter(
            *self,
            program.as_fd().as_raw_fd(),
            &program_info.name,
            program_info.id,
            options,
        )
        .map_err(|source| Error::system("attach classic traffic-control filter", source))?;
        Ok(TcFilter {
            hook: *self,
            info,
            attached: true,
        })
    }

    /// Queries an existing classifier by handle and priority.
    pub fn query(&self, identity: TcFilterId) -> Result<TcFilterInfo> {
        query_filter(*self, identity)
            .map_err(|source| Error::system("query classic traffic-control filter", source))
    }

    /// Removes an existing classifier by handle and priority.
    pub fn detach(&self, identity: TcFilterId) -> Result<()> {
        detach_filter(*self, identity)
            .map_err(|source| Error::system("detach classic traffic-control filter", source))
    }

    fn parent(self) -> io::Result<u32> {
        self.attach_point
            .parent()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))
    }
}

/// RAII owner of one classic traffic-control filter.
#[derive(Debug)]
pub struct TcFilter {
    hook: TcHook,
    info: TcFilterInfo,
    attached: bool,
}

impl TcFilter {
    /// Returns the filter's current known identity and program ID.
    pub const fn info(&self) -> TcFilterInfo {
        self.info
    }

    /// Re-queries the kernel and refreshes the program ID.
    pub fn refresh(&mut self) -> Result<TcFilterInfo> {
        self.info = self.hook.query(self.info.identity)?;
        Ok(self.info)
    }

    /// Removes the filter now.
    pub fn detach(mut self) -> Result<()> {
        self.hook.detach(self.info.identity)?;
        self.attached = false;
        Ok(())
    }

    /// Leaves the filter attached after this owner is dropped.
    pub fn persist(mut self) -> TcFilterInfo {
        self.attached = false;
        self.info
    }
}

impl Drop for TcFilter {
    fn drop(&mut self) {
        if self.attached {
            drop(detach_filter(self.hook, self.info.identity));
        }
    }
}

fn modify_clsact(interface_index: u32, message_type: u16) -> io::Result<()> {
    validate_interface_index(interface_index)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    let flags = if message_type == RTM_NEW_QDISC {
        netlink::REQUEST | netlink::ACK | netlink::CREATE | netlink::EXCLUSIVE
    } else {
        netlink::REQUEST | netlink::ACK
    };
    let payload = tc_payload(
        interface_index,
        make_handle(TC_HANDLE_CLSACT, 0),
        TC_HANDLE_CLSACT,
        0,
    )?;
    let mut request = Request::new(message_type, flags, &payload);
    request.push_attribute(TCA_KIND, b"clsact\0")?;
    netlink::transact(libc::NETLINK_ROUTE, request).map(drop)
}

fn attach_filter(
    hook: TcHook,
    program_fd: i32,
    program_name: &str,
    program_id: u32,
    options: TcAttachOptions,
) -> io::Result<TcFilterInfo> {
    let parent = hook.parent()?;
    let info = filter_info(options.priority);
    let payload = tc_payload(hook.interface_index, options.handle, parent, info)?;
    let exclusivity = if options.replace {
        netlink::REPLACE
    } else {
        netlink::EXCLUSIVE
    };
    let mut request = Request::new(
        RTM_NEW_FILTER,
        netlink::REQUEST | netlink::ACK | netlink::CREATE | netlink::ECHO | exclusivity,
        &payload,
    );
    request.push_attribute(TCA_KIND, b"bpf\0")?;
    let nested = request.begin_nested(TCA_OPTIONS);
    request.push_attribute(TCA_BPF_FD, &program_fd.to_ne_bytes())?;
    let label = format!("{program_name}:[{program_id}]");
    let mut label = label.into_bytes();
    label.push(0);
    request.push_attribute(TCA_BPF_NAME, &label)?;
    request.push_attribute(TCA_BPF_FLAGS, &TCA_BPF_FLAG_DIRECT_ACTION.to_ne_bytes())?;
    request.end_nested(nested)?;
    let responses = netlink::transact(libc::NETLINK_ROUTE, request)?;
    responses
        .iter()
        .find_map(|response| parse_filter(response).transpose())
        .transpose()?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "kernel did not echo the attached traffic-control filter",
            )
        })
}

fn query_filter(hook: TcHook, identity: TcFilterId) -> io::Result<TcFilterInfo> {
    let payload = tc_payload(
        hook.interface_index,
        identity.handle,
        hook.parent()?,
        filter_info(identity.priority),
    )?;
    let mut request = Request::new(RTM_GET_FILTER, netlink::REQUEST | netlink::ACK, &payload);
    request.push_attribute(TCA_KIND, b"bpf\0")?;
    let responses = netlink::transact(libc::NETLINK_ROUTE, request)?;
    responses
        .iter()
        .find_map(|response| parse_filter(response).transpose())
        .transpose()?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "TC filter was not found"))
}

fn detach_filter(hook: TcHook, identity: TcFilterId) -> io::Result<()> {
    let payload = tc_payload(
        hook.interface_index,
        identity.handle,
        hook.parent()?,
        filter_info(identity.priority),
    )?;
    let mut request = Request::new(RTM_DELETE_FILTER, netlink::REQUEST | netlink::ACK, &payload);
    request.push_attribute(TCA_KIND, b"bpf\0")?;
    netlink::transact(libc::NETLINK_ROUTE, request).map(drop)
}

fn parse_filter(response: &netlink::Response) -> io::Result<Option<TcFilterInfo>> {
    if response.message_type != RTM_NEW_FILTER || response.payload.len() < 20 {
        return Ok(None);
    }
    let handle = netlink::read_u32(&response.payload, 8)?;
    let priority = u16::try_from(netlink::read_u32(&response.payload, 16)? >> 16)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "TC priority is too large"))?;
    if handle == 0 || priority == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "kernel returned an incomplete TC filter identity",
        ));
    }
    let outer = netlink::attributes(&response.payload[20..])?;
    let options = netlink::attribute(&outer, TCA_OPTIONS).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "TC response has no classifier options",
        )
    })?;
    let options = netlink::attributes(options)?;
    let program_id = netlink::attribute(&options, TCA_BPF_ID)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "TC response has no BPF program ID",
            )
        })
        .and_then(|value| netlink::read_u32(value, 0))?;
    Ok(Some(TcFilterInfo {
        identity: TcFilterId { handle, priority },
        program_id,
    }))
}

fn tc_payload(interface_index: u32, handle: u32, parent: u32, info: u32) -> io::Result<[u8; 20]> {
    let interface_index = i32::try_from(interface_index)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface index is too large"))?;
    let mut payload = [0_u8; 20];
    payload[0] = libc::AF_UNSPEC as u8;
    payload[4..8].copy_from_slice(&interface_index.to_ne_bytes());
    payload[8..12].copy_from_slice(&handle.to_ne_bytes());
    payload[12..16].copy_from_slice(&parent.to_ne_bytes());
    payload[16..20].copy_from_slice(&info.to_ne_bytes());
    Ok(payload)
}

fn filter_info(priority: u16) -> u32 {
    u32::from(priority) << 16 | u32::from(ETHERNET_PROTOCOL_ALL.to_be())
}

const fn make_handle(major: u32, minor: u32) -> u32 {
    (major & TC_HANDLE_MAJOR_MASK) | (minor & !TC_HANDLE_MAJOR_MASK)
}

fn validate_interface_index(interface_index: u32) -> Result<()> {
    if interface_index == 0 || interface_index > i32::MAX as u32 {
        Err(Error::InvalidObject(
            "network interface index must be a positive i32".into(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_attach_points_map_to_kernel_parents() {
        assert_eq!(TcAttachPoint::Ingress.parent().unwrap(), 0xffff_fff2);
        assert_eq!(TcAttachPoint::Egress.parent().unwrap(), 0xffff_fff3);
        assert!(TcAttachPoint::Custom(0).parent().is_err());
        assert_eq!(
            TcAttachPoint::Custom(0x1234_5678).parent().unwrap(),
            0x1234_5678
        );
    }

    #[test]
    fn filter_protocol_is_stored_in_network_byte_order() {
        let info = filter_info(19);
        assert_eq!(info >> 16, 19);
        assert_eq!(info as u16, ETHERNET_PROTOCOL_ALL.to_be());
    }

    #[test]
    fn filter_identity_requires_both_kernel_keys() {
        assert!(TcFilterId::new(0, 1).is_err());
        assert!(TcFilterId::new(1, 0).is_err());
        assert_eq!(
            TcFilterId::new(1, 2).unwrap(),
            TcFilterId {
                handle: 1,
                priority: 2
            }
        );
    }
}
