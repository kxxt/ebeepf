use crate::{Error, Result};

/// One 64-bit eBPF instruction.
///
/// The register byte packs the destination register into its low nibble and
/// the source register into its high nibble, matching the kernel ABI.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct Instruction {
    /// Opcode.
    pub code: u8,
    registers: u8,
    /// Signed offset used by memory and branch instructions.
    pub offset: i16,
    /// Immediate operand.
    pub immediate: i32,
}

impl Instruction {
    /// Size of an encoded eBPF instruction.
    pub const SIZE: usize = 8;

    /// Creates an instruction from its components.
    pub const fn new(code: u8, destination: u8, source: u8, offset: i16, immediate: i32) -> Self {
        Self {
            code,
            registers: (destination & 0x0f) | ((source & 0x0f) << 4),
            offset,
            immediate,
        }
    }

    /// Returns the destination register number.
    pub const fn destination(self) -> u8 {
        self.registers & 0x0f
    }

    /// Returns the source register number.
    pub const fn source(self) -> u8 {
        self.registers >> 4
    }

    /// Changes the destination register.
    pub fn set_destination(&mut self, register: u8) -> Result<()> {
        validate_register(register)?;
        self.registers = (self.registers & 0xf0) | register;
        Ok(())
    }

    /// Changes the source register.
    pub fn set_source(&mut self, register: u8) -> Result<()> {
        validate_register(register)?;
        self.registers = (self.registers & 0x0f) | (register << 4);
        Ok(())
    }

    /// Decodes a sequence of native-endian instruction bytes.
    pub fn decode(bytes: &[u8]) -> Result<Vec<Self>> {
        if bytes.len() % Self::SIZE != 0 {
            return Err(Error::InvalidObject(format!(
                "instruction section is {} bytes; expected a multiple of {}",
                bytes.len(),
                Self::SIZE
            )));
        }

        Ok(bytes
            .chunks_exact(Self::SIZE)
            .map(|bytes| Self {
                code: bytes[0],
                registers: bytes[1],
                offset: i16::from_ne_bytes([bytes[2], bytes[3]]),
                immediate: i32::from_ne_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            })
            .collect())
    }
}

fn validate_register(register: u8) -> Result<()> {
    if register <= 10 {
        Ok(())
    } else {
        Err(Error::InvalidObject(format!(
            "eBPF register r{register} does not exist"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_accessors_preserve_the_other_nibble() {
        let mut instruction = Instruction::new(0x18, 1, 2, -3, 4);
        assert_eq!(instruction.destination(), 1);
        assert_eq!(instruction.source(), 2);

        instruction.set_destination(10).unwrap();
        assert_eq!(instruction.destination(), 10);
        assert_eq!(instruction.source(), 2);

        instruction.set_source(7).unwrap();
        assert_eq!(instruction.destination(), 10);
        assert_eq!(instruction.source(), 7);
        assert!(instruction.set_source(11).is_err());
    }

    #[test]
    fn decode_rejects_partial_instruction() {
        let error = Instruction::decode(&[0; 7]).unwrap_err();
        assert!(error.to_string().contains("multiple of 8"));
    }

    #[test]
    fn decode_uses_native_endian_operands() {
        let bytes = [0xb7, 0x01, 0xfe, 0xff, 0x78, 0x56, 0x34, 0x12];
        let instructions = Instruction::decode(&bytes).unwrap();
        assert_eq!(
            instructions,
            [Instruction::new(0xb7, 1, 0, -2, 0x1234_5678)]
        );
    }
}
