//! Legacy rtnetlink-managed XDP attachments.
//!
//! Prefer [`crate::Program::attach_xdp`] when the kernel supports XDP
//! `bpf_link`. This module covers persistent netlink attachments, including
//! atomic replacement and mode-specific queries.

use std::fs;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::PathBuf;

use bitflags::bitflags;

use crate::netlink::{self, Request};
use crate::{Error, Program, Result};

const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_SETLINK: u16 = 19;
const IFLA_XDP: u16 = 43;
const IFLA_XDP_FD: u16 = 1;
const IFLA_XDP_ATTACHED: u16 = 2;
const IFLA_XDP_FLAGS: u16 = 3;
const IFLA_XDP_PROG_ID: u16 = 4;
const IFLA_XDP_DRIVER_PROG_ID: u16 = 5;
const IFLA_XDP_SKB_PROG_ID: u16 = 6;
const IFLA_XDP_HARDWARE_PROG_ID: u16 = 7;
const IFLA_XDP_EXPECTED_FD: u16 = 8;

const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_GET_FAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const NETDEV_CMD_DEVICE_GET: u8 = 1;
const NETDEV_ATTR_INTERFACE_INDEX: u16 = 1;
const NETDEV_ATTR_XDP_FEATURES: u16 = 3;
const NETDEV_ATTR_XDP_ZERO_COPY_MAX_SEGMENTS: u16 = 4;

bitflags! {
    /// Flags selecting XDP replacement behavior and attachment mode.
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
    pub struct XdpFlags: u32 {
        /// Fail if an XDP program is already attached.
        const UPDATE_IF_NO_EXIST = 1 << 0;
        /// Attach in generic/SKB mode.
        const GENERIC = 1 << 1;
        /// Attach in native driver mode.
        const DRIVER = 1 << 2;
        /// Attach in hardware-offload mode.
        const HARDWARE = 1 << 3;
        /// Atomically replace the program named by `expected_program`.
        const REPLACE = 1 << 4;
    }
}

impl XdpFlags {
    const MODES: Self =
        Self::from_bits_retain(Self::GENERIC.bits() | Self::DRIVER.bits() | Self::HARDWARE.bits());

    fn validate_mode(self) -> Result<()> {
        let modes = (self & Self::MODES).bits();
        if modes.count_ones() > 1 {
            Err(Error::InvalidObject(
                "only one XDP attachment mode may be selected".into(),
            ))
        } else {
            Ok(())
        }
    }
}

bitflags! {
    /// XDP actions and driver capabilities reported by generic netlink.
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
    pub struct XdpFeatures: u64 {
        /// Basic abort, drop, pass, and transmit actions.
        const BASIC = 1;
        /// Redirect action support.
        const REDIRECT = 1 << 1;
        /// Driver transmit callback support.
        const DRIVER_TRANSMIT = 1 << 2;
        /// AF_XDP zero-copy support.
        const XSK_ZERO_COPY = 1 << 3;
        /// Hardware offload support.
        const HARDWARE_OFFLOAD = 1 << 4;
        /// Fragmented receive-buffer support.
        const RECEIVE_SCATTER_GATHER = 1 << 5;
        /// Fragmented driver-transmit support.
        const TRANSMIT_SCATTER_GATHER = 1 << 6;
    }
}

/// How XDP is currently attached to an interface.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum XdpAttachMode {
    /// No XDP program is attached.
    None,
    /// Native driver mode.
    Driver,
    /// Generic/SKB mode.
    Generic,
    /// Hardware-offload mode.
    Hardware,
    /// Different programs are attached in multiple modes.
    Multiple,
    /// A mode introduced after this crate version.
    Other(u8),
}

impl XdpAttachMode {
    const fn from_raw(value: u8) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Driver,
            2 => Self::Generic,
            3 => Self::Hardware,
            4 => Self::Multiple,
            value => Self::Other(value),
        }
    }
}

/// Atomic-replacement options for a netlink XDP update.
#[derive(Clone, Copy, Debug, Default)]
pub struct XdpAttachOptions<'fd> {
    /// Mode and update behavior.
    pub flags: XdpFlags,
    /// Existing program which must still be attached before replacement.
    pub expected_program: Option<BorrowedFd<'fd>>,
}

impl<'fd> XdpAttachOptions<'fd> {
    /// Creates default update options.
    pub const fn new() -> Self {
        Self {
            flags: XdpFlags::empty(),
            expected_program: None,
        }
    }

    /// Selects mode or update flags.
    pub const fn with_flags(mut self, flags: XdpFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Requires this exact old program before atomically replacing it.
    pub fn replacing(mut self, program: &'fd Program) -> Self {
        self.expected_program = Some(program.as_fd());
        self.flags.insert(XdpFlags::REPLACE);
        self
    }
}

/// Current XDP state for one network interface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XdpInfo {
    /// Overall attached program ID when exactly one mode is active.
    pub program_id: u32,
    /// Native driver-mode program ID.
    pub driver_program_id: u32,
    /// Generic/SKB-mode program ID.
    pub generic_program_id: u32,
    /// Hardware-offload program ID.
    pub hardware_program_id: u32,
    /// Current attachment mode.
    pub attach_mode: XdpAttachMode,
    /// Driver feature flags, when the kernel's `netdev` family is available.
    pub features: Option<XdpFeatures>,
    /// Maximum `AF_XDP` zero-copy fragments, when reported by the kernel.
    pub zero_copy_max_segments: Option<u32>,
}

impl XdpInfo {
    /// Returns the program ID selected by one optional mode flag.
    pub fn program_id_for(self, flags: XdpFlags) -> Result<Option<u32>> {
        validate_query_flags(flags)?;
        let id = if flags.contains(XdpFlags::DRIVER) {
            self.driver_program_id
        } else if flags.contains(XdpFlags::GENERIC) {
            self.generic_program_id
        } else if flags.contains(XdpFlags::HARDWARE) {
            self.hardware_program_id
        } else if self.attach_mode == XdpAttachMode::Multiple {
            0
        } else {
            self.program_id
        };
        Ok((id != 0).then_some(id))
    }
}

/// A network interface on which persistent XDP state is managed by rtnetlink.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Xdp {
    interface_index: u32,
}

impl Xdp {
    /// Selects an interface by its positive kernel index.
    pub fn new(interface_index: u32) -> Result<Self> {
        validate_interface_index(interface_index)?;
        Ok(Self { interface_index })
    }

    /// Selects an interface by name through sysfs.
    pub fn from_name(name: &str) -> Result<Self> {
        if name.is_empty() || name.as_bytes().contains(&b'/') {
            return Err(Error::InvalidObject(
                "network interface name is empty or contains `/`".into(),
            ));
        }
        let path = PathBuf::from("/sys/class/net").join(name).join("ifindex");
        let text = fs::read_to_string(&path).map_err(|source| Error::File {
            operation: "read network interface index",
            path,
            source,
        })?;
        let index = text.trim().parse().map_err(|_| {
            Error::InvalidObject(format!("interface `{name}` has a non-integer index"))
        })?;
        Self::new(index)
    }

    /// Returns the selected kernel interface index.
    pub const fn interface_index(self) -> u32 {
        self.interface_index
    }

    /// Creates or replaces a persistent rtnetlink XDP attachment.
    pub fn attach(&self, program: &Program, options: XdpAttachOptions<'_>) -> Result<()> {
        set_link(self.interface_index, program.as_fd().as_raw_fd(), options)
            .map_err(|source| Error::system("attach XDP program through rtnetlink", source))
    }

    /// Removes a persistent rtnetlink XDP attachment.
    ///
    /// Supplying `expected_program` makes the removal atomic with respect to
    /// another process replacing the interface's program.
    pub fn detach(&self, options: XdpAttachOptions<'_>) -> Result<()> {
        set_link(self.interface_index, -1, options)
            .map_err(|source| Error::system("detach XDP program through rtnetlink", source))
    }

    /// Queries attached program IDs, mode, and available driver features.
    pub fn query(&self) -> Result<XdpInfo> {
        let mut info = query_link(self.interface_index)
            .map_err(|source| Error::system("query XDP interface state", source))?;
        match query_features(self.interface_index) {
            Ok(Some((features, max_segments))) => {
                info.features = Some(features);
                info.zero_copy_max_segments = max_segments;
            }
            Ok(None) => {}
            Err(source) => return Err(Error::system("query XDP interface features", source)),
        }
        Ok(info)
    }

    /// Returns the attached ID in one optional mode.
    pub fn program_id(&self, flags: XdpFlags) -> Result<Option<u32>> {
        self.query()?.program_id_for(flags)
    }
}

fn set_link(
    interface_index: u32,
    program_fd: i32,
    mut options: XdpAttachOptions<'_>,
) -> io::Result<()> {
    validate_interface_index(interface_index).map_err(error_to_io)?;
    options.flags.validate_mode().map_err(error_to_io)?;
    let expected_fd = options.expected_program.map(|fd| fd.as_raw_fd());
    if expected_fd.is_some() {
        options.flags.insert(XdpFlags::REPLACE);
    } else if options.flags.contains(XdpFlags::REPLACE) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "XDP REPLACE requires an expected program descriptor",
        ));
    }
    let payload = interface_info_payload(libc::AF_UNSPEC as u8, interface_index)?;
    let mut request = Request::new(RTM_SETLINK, netlink::REQUEST | netlink::ACK, &payload);
    let nested = request.begin_nested(IFLA_XDP);
    request.push_attribute(IFLA_XDP_FD, &program_fd.to_ne_bytes())?;
    if !options.flags.is_empty() {
        request.push_attribute(IFLA_XDP_FLAGS, &options.flags.bits().to_ne_bytes())?;
    }
    if let Some(fd) = expected_fd {
        request.push_attribute(IFLA_XDP_EXPECTED_FD, &fd.to_ne_bytes())?;
    }
    request.end_nested(nested)?;
    netlink::transact(libc::NETLINK_ROUTE, request).map(drop)
}

fn query_link(interface_index: u32) -> io::Result<XdpInfo> {
    validate_interface_index(interface_index).map_err(error_to_io)?;
    let payload = interface_info_payload(libc::AF_PACKET as u8, 0)?;
    let request = Request::new(RTM_GETLINK, netlink::REQUEST | netlink::DUMP, &payload);
    let responses = netlink::transact(libc::NETLINK_ROUTE, request)?;
    for response in responses {
        if response.message_type != RTM_NEWLINK || response.payload.len() < 16 {
            continue;
        }
        let index = netlink::read_u32(&response.payload, 4)?;
        if index != interface_index {
            continue;
        }
        let outer = netlink::attributes(&response.payload[16..])?;
        let Some(xdp) = netlink::attribute(&outer, IFLA_XDP) else {
            return Ok(empty_info());
        };
        let attributes = netlink::attributes(xdp)?;
        return Ok(XdpInfo {
            program_id: optional_u32(&attributes, IFLA_XDP_PROG_ID)?,
            driver_program_id: optional_u32(&attributes, IFLA_XDP_DRIVER_PROG_ID)?,
            generic_program_id: optional_u32(&attributes, IFLA_XDP_SKB_PROG_ID)?,
            hardware_program_id: optional_u32(&attributes, IFLA_XDP_HARDWARE_PROG_ID)?,
            attach_mode: netlink::attribute(&attributes, IFLA_XDP_ATTACHED)
                .map(netlink::read_u8)
                .transpose()?
                .map_or(XdpAttachMode::None, XdpAttachMode::from_raw),
            features: None,
            zero_copy_max_segments: None,
        });
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "network interface was not returned by rtnetlink",
    ))
}

fn query_features(interface_index: u32) -> io::Result<Option<(XdpFeatures, Option<u32>)>> {
    let family = match resolve_generic_family("netdev") {
        Ok(family) => family,
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut request = Request::new(
        family,
        netlink::REQUEST,
        &generic_header(NETDEV_CMD_DEVICE_GET, 1),
    );
    request.push_attribute(NETDEV_ATTR_INTERFACE_INDEX, &interface_index.to_ne_bytes())?;
    let responses = netlink::transact(libc::NETLINK_GENERIC, request)?;
    for response in responses {
        if response.message_type != family || response.payload.len() < 4 {
            continue;
        }
        let attributes = netlink::attributes(&response.payload[4..])?;
        let Some(features) = netlink::attribute(&attributes, NETDEV_ATTR_XDP_FEATURES) else {
            continue;
        };
        let features = XdpFeatures::from_bits_retain(netlink::read_u64(features, 0)?);
        let max_segments = netlink::attribute(&attributes, NETDEV_ATTR_XDP_ZERO_COPY_MAX_SEGMENTS)
            .map(|value| netlink::read_u32(value, 0))
            .transpose()?;
        return Ok(Some((features, max_segments)));
    }
    Ok(None)
}

fn resolve_generic_family(name: &str) -> io::Result<u16> {
    let mut request = Request::new(
        GENL_ID_CTRL,
        netlink::REQUEST,
        &generic_header(CTRL_CMD_GET_FAMILY, 2),
    );
    let mut name = name.as_bytes().to_vec();
    name.push(0);
    request.push_attribute(CTRL_ATTR_FAMILY_NAME, &name)?;
    let responses = netlink::transact(libc::NETLINK_GENERIC, request)?;
    for response in responses {
        if response.message_type != GENL_ID_CTRL || response.payload.len() < 4 {
            continue;
        }
        let attributes = netlink::attributes(&response.payload[4..])?;
        if let Some(id) = netlink::attribute(&attributes, CTRL_ATTR_FAMILY_ID) {
            return netlink::read_u16(id, 0);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "generic netlink family was not found",
    ))
}

fn generic_header(command: u8, version: u8) -> [u8; 4] {
    [command, version, 0, 0]
}

fn interface_info_payload(family: u8, interface_index: u32) -> io::Result<[u8; 16]> {
    let interface_index = i32::try_from(interface_index)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface index is too large"))?;
    let mut payload = [0_u8; 16];
    payload[0] = family;
    payload[4..8].copy_from_slice(&interface_index.to_ne_bytes());
    Ok(payload)
}

fn optional_u32(attributes: &[netlink::Attribute<'_>], kind: u16) -> io::Result<u32> {
    netlink::attribute(attributes, kind)
        .map(|value| netlink::read_u32(value, 0))
        .transpose()
        .map(Option::unwrap_or_default)
}

const fn empty_info() -> XdpInfo {
    XdpInfo {
        program_id: 0,
        driver_program_id: 0,
        generic_program_id: 0,
        hardware_program_id: 0,
        attach_mode: XdpAttachMode::None,
        features: None,
        zero_copy_max_segments: None,
    }
}

fn validate_query_flags(flags: XdpFlags) -> Result<()> {
    flags.validate_mode()?;
    if !(flags - XdpFlags::MODES).is_empty() {
        return Err(Error::InvalidObject(
            "XDP queries only accept a mode flag".into(),
        ));
    }
    Ok(())
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

fn error_to_io(error: Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_validation_rejects_multiple_modes() {
        assert!((XdpFlags::DRIVER | XdpFlags::GENERIC)
            .validate_mode()
            .is_err());
        assert!(XdpFlags::HARDWARE.validate_mode().is_ok());
    }

    #[test]
    fn program_id_selection_handles_multi_mode() {
        let info = XdpInfo {
            program_id: 10,
            driver_program_id: 11,
            generic_program_id: 12,
            hardware_program_id: 13,
            attach_mode: XdpAttachMode::Multiple,
            features: None,
            zero_copy_max_segments: None,
        };
        assert_eq!(info.program_id_for(XdpFlags::DRIVER).unwrap(), Some(11));
        assert_eq!(info.program_id_for(XdpFlags::empty()).unwrap(), None);
        assert!(info.program_id_for(XdpFlags::REPLACE).is_err());
    }

    #[test]
    fn loopback_query_is_safe_when_the_interface_exists() {
        let Ok(loopback) = Xdp::from_name("lo") else {
            return;
        };
        let info = loopback.query().unwrap();
        assert_eq!(info.attach_mode, XdpAttachMode::None);
    }
}
