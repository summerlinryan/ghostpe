use std::fmt::Display;
use anyhow::Result;
use std::fs::File;
use std::io::Read;
use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
use windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;

pub struct PE {
    data: Vec<u8>,
    pub dos_header: IMAGE_DOS_HEADER,
    pub nt_header: IMAGE_NT_HEADERS64,
}

impl PE {
    pub fn load_from_file(file: &str) -> Result<Self> {
        let mut file = File::open(file)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Ok(Self::load(data)?)
    }

    pub fn load(data: Vec<u8>) -> Result<Self> {
        let (dos_header, nt_header) = Self::parse_headers(&data)?;
        Ok(Self{
            data,
            dos_header,
            nt_header
        })
    }

    fn parse_headers(data: &Vec<u8>) -> Result<(IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64)> {
        const DOS_MAGIC: u16 = 0x5A4D; // MZ
        const NT_MAGIC: u32 = 0x4550;  // PE\0\0

        let dos_header = unsafe {
            *(data.as_ptr() as *const IMAGE_DOS_HEADER)
        };

        if dos_header.e_magic != DOS_MAGIC {
            return Err(anyhow::anyhow!("Invalid DOS header. Expected 0x{:x}, got 0x{:x}", DOS_MAGIC, dos_header.e_magic));
        }

        let nt_header = unsafe {
            *(data.as_ptr().offset(dos_header.e_lfanew as isize) as *const IMAGE_NT_HEADERS64)
        };

        if nt_header.Signature != NT_MAGIC {
            return Err(anyhow::anyhow!("Invalid NT header. Expected 0x{:x}, got 0x{:x}", NT_MAGIC, nt_header.Signature));
        }

        Ok((dos_header, nt_header))
    }
}