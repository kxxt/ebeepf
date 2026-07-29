//! Small, private netlink transport used by the XDP and traffic-control APIs.
//!
//! This deliberately implements only the stable message framing and attribute
//! encoding needed by this crate. The public networking APIs never expose raw
//! pointers, native structs, or netlink sockets.

use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicU32, Ordering};

pub(crate) const HEADER_LENGTH: usize = 16;
pub(crate) const ATTRIBUTE_HEADER_LENGTH: usize = 4;

pub(crate) const REQUEST: u16 = 1;
pub(crate) const MULTI: u16 = 2;
pub(crate) const ACK: u16 = 4;
pub(crate) const ECHO: u16 = 8;
pub(crate) const ROOT: u16 = 0x100;
pub(crate) const MATCH: u16 = 0x200;
pub(crate) const DUMP: u16 = ROOT | MATCH;
pub(crate) const REPLACE: u16 = 0x100;
pub(crate) const EXCLUSIVE: u16 = 0x200;
pub(crate) const CREATE: u16 = 0x400;

const MESSAGE_NOOP: u16 = 1;
const MESSAGE_ERROR: u16 = 2;
const MESSAGE_DONE: u16 = 3;
const ATTRIBUTE_F_NESTED: u16 = 1 << 15;
const ATTRIBUTE_TYPE_MASK: u16 = 0x3fff;
const SOL_NETLINK: libc::c_int = 270;
const NETLINK_EXT_ACK: libc::c_int = 11;

static NEXT_SEQUENCE: AtomicU32 = AtomicU32::new(1);

/// An encoded netlink request.
pub(crate) struct Request {
    bytes: Vec<u8>,
}

impl Request {
    pub(crate) fn new(message_type: u16, flags: u16, payload: &[u8]) -> Self {
        let mut bytes = vec![0_u8; HEADER_LENGTH];
        write_u16(&mut bytes, 4, message_type);
        write_u16(&mut bytes, 6, flags);
        bytes.extend_from_slice(payload);
        align(&mut bytes);
        Self { bytes }
    }

    pub(crate) fn push_attribute(&mut self, kind: u16, value: &[u8]) -> io::Result<()> {
        let length = ATTRIBUTE_HEADER_LENGTH
            .checked_add(value.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "attribute is too large"))?;
        let length = u16::try_from(length)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "attribute is too large"))?;
        self.bytes.extend_from_slice(&length.to_ne_bytes());
        self.bytes.extend_from_slice(&kind.to_ne_bytes());
        self.bytes.extend_from_slice(value);
        align(&mut self.bytes);
        Ok(())
    }

    pub(crate) fn begin_nested(&mut self, kind: u16) -> NestedAttribute {
        let offset = self.bytes.len();
        self.bytes.extend_from_slice(&0_u16.to_ne_bytes());
        self.bytes
            .extend_from_slice(&(kind | ATTRIBUTE_F_NESTED).to_ne_bytes());
        NestedAttribute(offset)
    }

    pub(crate) fn end_nested(&mut self, nested: NestedAttribute) -> io::Result<()> {
        let length = self.bytes.len().checked_sub(nested.0).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid nested attribute")
        })?;
        let length = u16::try_from(length).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "nested attribute is too large")
        })?;
        self.bytes[nested.0..nested.0 + 2].copy_from_slice(&length.to_ne_bytes());
        align(&mut self.bytes);
        Ok(())
    }

    fn prepare(&mut self, sequence: u32) -> io::Result<()> {
        let length = u32::try_from(self.bytes.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "request is too large"))?;
        self.bytes[..4].copy_from_slice(&length.to_ne_bytes());
        self.bytes[8..12].copy_from_slice(&sequence.to_ne_bytes());
        self.bytes[12..16].fill(0);
        Ok(())
    }

    fn flags(&self) -> u16 {
        read_u16(&self.bytes, 6).unwrap_or_default()
    }
}

#[derive(Clone, Copy)]
pub(crate) struct NestedAttribute(usize);

/// One data message returned by a netlink transaction.
#[derive(Debug)]
pub(crate) struct Response {
    pub message_type: u16,
    pub payload: Vec<u8>,
}

/// Sends a request and collects every data response before its ACK or DONE.
pub(crate) fn transact(protocol: libc::c_int, mut request: Request) -> io::Result<Vec<Response>> {
    let sequence = NEXT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    request.prepare(sequence)?;
    let request_flags = request.flags();
    let (socket, port_id) = open(protocol)?;
    send(&socket, &request.bytes)?;

    let mut responses = Vec::new();
    let mut multipart = false;
    loop {
        let packet = receive(&socket)?;
        let mut offset = 0;
        let mut terminal = false;
        while offset + HEADER_LENGTH <= packet.len() {
            let length = read_u32(&packet, offset)? as usize;
            if length < HEADER_LENGTH || offset + length > packet.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "malformed netlink response length",
                ));
            }
            let message_type = read_u16(&packet, offset + 4)?;
            let flags = read_u16(&packet, offset + 6)?;
            let message_sequence = read_u32(&packet, offset + 8)?;
            let message_port = read_u32(&packet, offset + 12)?;
            if message_sequence != sequence {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "netlink response sequence does not match request",
                ));
            }
            if message_port != port_id {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "netlink response has an unexpected port ID",
                ));
            }
            multipart |= flags & MULTI != 0;
            let payload = &packet[offset + HEADER_LENGTH..offset + length];
            match message_type {
                MESSAGE_NOOP => {}
                MESSAGE_ERROR => {
                    let error = read_i32(payload, 0)?;
                    if error != 0 {
                        return Err(io::Error::from_raw_os_error(error.saturating_neg()));
                    }
                    terminal = true;
                }
                MESSAGE_DONE => terminal = true,
                _ => responses.push(Response {
                    message_type,
                    payload: payload.to_vec(),
                }),
            }
            offset = aligned_length(offset + length);
        }
        if terminal || (!multipart && request_flags & ACK == 0 && !responses.is_empty()) {
            return Ok(responses);
        }
    }
}

/// A decoded netlink attribute.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Attribute<'a> {
    pub kind: u16,
    pub value: &'a [u8],
}

pub(crate) fn attributes(mut bytes: &[u8]) -> io::Result<Vec<Attribute<'_>>> {
    let mut result = Vec::new();
    while bytes.len() >= ATTRIBUTE_HEADER_LENGTH {
        let length = read_u16(bytes, 0)? as usize;
        if length < ATTRIBUTE_HEADER_LENGTH || length > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed netlink attribute",
            ));
        }
        result.push(Attribute {
            kind: read_u16(bytes, 2)? & ATTRIBUTE_TYPE_MASK,
            value: &bytes[ATTRIBUTE_HEADER_LENGTH..length],
        });
        let consumed = aligned_length(length);
        if consumed > bytes.len() {
            if length == bytes.len() {
                break;
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated netlink attribute padding",
            ));
        }
        bytes = &bytes[consumed..];
    }
    if bytes.iter().any(|byte| *byte != 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing bytes after netlink attributes",
        ));
    }
    Ok(result)
}

pub(crate) fn attribute<'a>(attributes: &'a [Attribute<'a>], kind: u16) -> Option<&'a [u8]> {
    attributes
        .iter()
        .find(|attribute| attribute.kind == kind)
        .map(|attribute| attribute.value)
}

pub(crate) fn read_u8(bytes: &[u8]) -> io::Result<u8> {
    bytes.first().copied().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "netlink integer attribute is truncated",
        )
    })
}

pub(crate) fn read_u16(bytes: &[u8], offset: usize) -> io::Result<u16> {
    read_array(bytes, offset).map(u16::from_ne_bytes)
}

pub(crate) fn read_u32(bytes: &[u8], offset: usize) -> io::Result<u32> {
    read_array(bytes, offset).map(u32::from_ne_bytes)
}

pub(crate) fn read_u64(bytes: &[u8], offset: usize) -> io::Result<u64> {
    read_array(bytes, offset).map(u64::from_ne_bytes)
}

fn read_i32(bytes: &[u8], offset: usize) -> io::Result<i32> {
    read_array(bytes, offset).map(i32::from_ne_bytes)
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> io::Result<[u8; N]> {
    bytes
        .get(offset..offset + N)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "netlink integer attribute is truncated",
            )
        })
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_ne_bytes());
}

fn align(bytes: &mut Vec<u8>) {
    bytes.resize(aligned_length(bytes.len()), 0);
}

const fn aligned_length(length: usize) -> usize {
    (length + 3) & !3
}

fn open(protocol: libc::c_int) -> io::Result<(OwnedFd, u32)> {
    // SAFETY: `socket` has no pointer arguments. A nonnegative descriptor is
    // immediately transferred into `OwnedFd`.
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            protocol,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a fresh descriptor returned by `socket`.
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let one: libc::c_int = 1;
    // Extended ACK support is optional and only improves error diagnostics.
    // SAFETY: The option points to a live integer with its exact byte length.
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            SOL_NETLINK,
            NETLINK_EXT_ACK,
            (&one as *const libc::c_int).cast(),
            mem::size_of_val(&one) as libc::socklen_t,
        );
    }

    // SAFETY: A zeroed sockaddr_nl is a valid unnamed netlink address after
    // setting its family. The kernel fills the port ID during bind.
    let mut address: libc::sockaddr_nl = unsafe { mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    // SAFETY: The pointer and length describe the initialized address above.
    if unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&address as *const libc::sockaddr_nl).cast(),
            mem::size_of_val(&address) as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut length = mem::size_of_val(&address) as libc::socklen_t;
    // SAFETY: The mutable address and length are valid output buffers.
    if unsafe {
        libc::getsockname(
            socket.as_raw_fd(),
            (&mut address as *mut libc::sockaddr_nl).cast(),
            &mut length,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if length as usize != mem::size_of_val(&address) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "kernel returned an unexpected netlink address size",
        ));
    }
    Ok((socket, address.nl_pid))
}

fn send(socket: &OwnedFd, bytes: &[u8]) -> io::Result<()> {
    // SAFETY: A zeroed destination with AF_NETLINK and pid zero addresses the
    // kernel. Both pointers remain live throughout `sendto`.
    let mut kernel: libc::sockaddr_nl = unsafe { mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let sent = unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            bytes.as_ptr().cast(),
            bytes.len(),
            0,
            (&kernel as *const libc::sockaddr_nl).cast(),
            mem::size_of_val(&kernel) as libc::socklen_t,
        )
    };
    if sent < 0 {
        Err(io::Error::last_os_error())
    } else if sent as usize != bytes.len() {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "netlink request was only partially sent",
        ))
    } else {
        Ok(())
    }
}

fn receive(socket: &OwnedFd) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0_u8; 64 * 1024];
    loop {
        // SAFETY: The vector owns a writable allocation of the advertised
        // length and the kernel initializes the returned prefix.
        let received = unsafe {
            libc::recv(
                socket.as_raw_fd(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                0,
            )
        };
        if received >= 0 {
            bytes.truncate(received as usize);
            return Ok(bytes);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attributes_round_trip_nested_values() {
        let mut request = Request::new(99, REQUEST, &[]);
        request.push_attribute(1, &17_u32.to_ne_bytes()).unwrap();
        let nested = request.begin_nested(2);
        request.push_attribute(3, &[9]).unwrap();
        request.end_nested(nested).unwrap();

        let outer = attributes(&request.bytes[HEADER_LENGTH..]).unwrap();
        assert_eq!(read_u32(attribute(&outer, 1).unwrap(), 0).unwrap(), 17);
        let inner = attributes(attribute(&outer, 2).unwrap()).unwrap();
        assert_eq!(read_u8(attribute(&inner, 3).unwrap()).unwrap(), 9);
    }

    #[test]
    fn malformed_attributes_are_rejected() {
        assert!(attributes(&[3, 0, 1, 0]).is_err());
        assert!(attributes(&[8, 0, 1, 0, 0, 0, 0]).is_err());
    }
}
