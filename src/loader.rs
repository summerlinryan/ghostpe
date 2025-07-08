use anyhow::Result;
use std::fs::File;
use std::io::Read;
use std::mem::size_of;
use windows::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc};
use windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;

pub struct PE {
    data: Vec<u8>,
    dos_header: IMAGE_DOS_HEADER,
    nt_header: IMAGE_NT_HEADERS64,
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
        Ok(Self {
            data,
            dos_header,
            nt_header,
        })
    }

    pub fn execute_from_file(file: &str) -> Result<()> {
        let mut file = File::open(file)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Self::execute(data)
    }

    pub fn execute(data: Vec<u8>) -> Result<()> {
        let (dos_header, nt_header) = Self::parse_headers(&data)?;

        let pe = Self {
            data,
            dos_header,
            nt_header,
        };

        pe.load_into_memory()?;

        // pe.perform_relocations()?;
        // pe.resolve_imports()?;
        // pe.handle_tls_callbacks()?;
        // pe.call_entry_point()
        Ok(())
    }

    fn parse_headers(data: &Vec<u8>) -> Result<(IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64)> {
        const DOS_MAGIC: u16 = 0x5A4D; // MZ
        const NT_MAGIC: u32 = 0x4550; // PE\0\0

        if data.len() < size_of::<IMAGE_DOS_HEADER>() {
            return Err(anyhow::anyhow!("Data too small for DOS header"));
        }

        let dos_header = unsafe { *(data.as_ptr() as *const IMAGE_DOS_HEADER) };

        if dos_header.e_magic != DOS_MAGIC {
            return Err(anyhow::anyhow!(
                "Invalid DOS header. Expected 0x{:x}, got 0x{:x}",
                DOS_MAGIC,
                dos_header.e_magic
            ));
        }

        // Check if we have enough data for NT header
        let nt_header_offset = dos_header.e_lfanew as usize;
        if nt_header_offset + size_of::<IMAGE_NT_HEADERS64>() > data.len() {
            return Err(anyhow::anyhow!("Data too small for NT header"));
        }

        let nt_header = unsafe {
            *(data.as_ptr().offset(dos_header.e_lfanew as isize) as *const IMAGE_NT_HEADERS64)
        };

        if nt_header.Signature != NT_MAGIC {
            return Err(anyhow::anyhow!(
                "Invalid NT header. Expected 0x{:x}, got 0x{:x}",
                NT_MAGIC,
                nt_header.Signature
            ));
        }

        Ok((dos_header, nt_header))
    }

    fn load_into_memory(&self) -> Result<()> {
        let image_size = self.nt_header.OptionalHeader.SizeOfImage as usize;
        let image_base = unsafe {
            VirtualAlloc(
                Some(std::ptr::null_mut()),
                image_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };

        if image_base.is_null() {
            return Err(anyhow::anyhow!(
                "Failed to allocate {} bytes for the image",
                image_size
            ));
        }

        unsafe {
            std::ptr::copy_nonoverlapping(
                self.data.as_ptr(),
                image_base as *mut u8,
                self.nt_header.OptionalHeader.SizeOfHeaders as usize,
            );
        }

        let nt_header_offset = self.dos_header.e_lfanew as usize;
        let first_section_offset = unsafe {
            self.data
                .as_ptr()
                .add(nt_header_offset + size_of::<IMAGE_NT_HEADERS64>())
        } as *const IMAGE_SECTION_HEADER;

        for i in 0..self.nt_header.FileHeader.NumberOfSections {
            let current_section = unsafe { &*first_section_offset.add(i as usize) };
            let src = unsafe {
                self.data
                    .as_ptr()
                    .add(current_section.PointerToRawData as usize)
            };
            let dest = image_base as usize + current_section.VirtualAddress as usize;
            let size = current_section.SizeOfRawData as usize;

            unsafe { std::ptr::copy_nonoverlapping(src, dest as *mut u8, size) }
        }

        Ok(())
    }

    fn perform_relocations(&self) -> Result<()> {
        todo!()
    }

    fn resolve_imports(&self) -> Result<()> {
        todo!()
    }

    fn handle_tls_callbacks(&self) -> Result<()> {
        todo!()
    }

    fn call_entry_point(&self) -> Result<()> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use windows::Win32::System::{
        Diagnostics::Debug::{
            IMAGE_DLL_CHARACTERISTICS, IMAGE_FILE_CHARACTERISTICS, IMAGE_OPTIONAL_HEADER_MAGIC,
            IMAGE_SECTION_CHARACTERISTICS, IMAGE_SUBSYSTEM,
        },
        SystemInformation::IMAGE_FILE_MACHINE,
    };

    use super::*;

    // Helper function to create a minimal valid PE file
    fn create_minimal_pe() -> Vec<u8> {
        let mut data = Vec::new();

        // DOS Header (64 bytes)
        let dos_header = IMAGE_DOS_HEADER {
            e_magic: 0x5A4D, // MZ
            e_cblp: 0x90,
            e_cp: 0x3,
            e_crlc: 0,
            e_cparhdr: 0x4,
            e_minalloc: 0,
            e_maxalloc: 0xFFFF,
            e_ss: 0,
            e_sp: 0xB8,
            e_csum: 0,
            e_ip: 0,
            e_cs: 0,
            e_lfarlc: 0x40,
            e_ovno: 0,
            e_res: [0; 4],
            e_oemid: 0,
            e_oeminfo: 0,
            e_res2: [0; 10],
            e_lfanew: 0x80, // NT header starts at offset 0x80
        };

        // Add DOS header bytes
        unsafe {
            let header_bytes = std::slice::from_raw_parts(
                &dos_header as *const _ as *const u8,
                size_of::<IMAGE_DOS_HEADER>(),
            );
            data.extend_from_slice(header_bytes);
        }

        // Pad to NT header offset
        while data.len() < 0x80 {
            data.push(0);
        }

        // NT Header
        let nt_header = IMAGE_NT_HEADERS64 {
            Signature: 0x4550, // PE\0\0
            FileHeader: windows::Win32::System::Diagnostics::Debug::IMAGE_FILE_HEADER {
                Machine: IMAGE_FILE_MACHINE(0x8664), // AMD64
                NumberOfSections: 1,
                TimeDateStamp: 0,
                PointerToSymbolTable: 0,
                NumberOfSymbols: 0,
                SizeOfOptionalHeader: size_of::<
                    windows::Win32::System::Diagnostics::Debug::IMAGE_OPTIONAL_HEADER64,
                >() as u16,
                Characteristics: IMAGE_FILE_CHARACTERISTICS(0x22), // IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL
            },
            OptionalHeader: windows::Win32::System::Diagnostics::Debug::IMAGE_OPTIONAL_HEADER64 {
                Magic: IMAGE_OPTIONAL_HEADER_MAGIC(0x20B), // PE32+
                MajorLinkerVersion: 0,
                MinorLinkerVersion: 0,
                SizeOfCode: 0x1000,
                SizeOfInitializedData: 0x1000,
                SizeOfUninitializedData: 0,
                AddressOfEntryPoint: 0x1000,
                BaseOfCode: 0x1000,
                ImageBase: 0x140000000,
                SectionAlignment: 0x1000,
                FileAlignment: 0x200,
                MajorOperatingSystemVersion: 6,
                MinorOperatingSystemVersion: 0,
                MajorImageVersion: 0,
                MinorImageVersion: 0,
                MajorSubsystemVersion: 6,
                MinorSubsystemVersion: 0,
                Win32VersionValue: 0,
                SizeOfImage: 0x3000,
                SizeOfHeaders: 0x200,
                CheckSum: 0,
                Subsystem: IMAGE_SUBSYSTEM(2), // IMAGE_SUBSYSTEM_WINDOWS_GUI
                DllCharacteristics: IMAGE_DLL_CHARACTERISTICS(0),
                SizeOfStackReserve: 0x100000,
                SizeOfStackCommit: 0x1000,
                SizeOfHeapReserve: 0x100000,
                SizeOfHeapCommit: 0x1000,
                LoaderFlags: 0,
                NumberOfRvaAndSizes: 16,
                DataDirectory: [windows::Win32::System::Diagnostics::Debug::IMAGE_DATA_DIRECTORY {
                    VirtualAddress: 0,
                    Size: 0,
                }; 16],
            },
        };

        // Add NT header bytes
        unsafe {
            let header_bytes = std::slice::from_raw_parts(
                &nt_header as *const _ as *const u8,
                size_of::<IMAGE_NT_HEADERS64>(),
            );
            data.extend_from_slice(header_bytes);
        }

        // Section header
        let section_header = IMAGE_SECTION_HEADER {
            Name: [b'.', b't', b'e', b'x', b't', 0, 0, 0],
            Misc: windows::Win32::System::Diagnostics::Debug::IMAGE_SECTION_HEADER_0 {
                VirtualSize: 0x1000,
            },
            VirtualAddress: 0x1000,
            SizeOfRawData: 0x200,
            PointerToRawData: 0x200,
            PointerToRelocations: 0,
            PointerToLinenumbers: 0,
            NumberOfRelocations: 0,
            NumberOfLinenumbers: 0,
            Characteristics: IMAGE_SECTION_CHARACTERISTICS(0x60000020), // IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
        };

        // Add section header bytes
        unsafe {
            let header_bytes = std::slice::from_raw_parts(
                &section_header as *const _ as *const u8,
                size_of::<IMAGE_SECTION_HEADER>(),
            );
            data.extend_from_slice(header_bytes);
        }

        // Pad to section data
        while data.len() < 0x200 {
            data.push(0);
        }

        // Add some dummy section data
        for _ in 0..0x200 {
            data.push(0x90); // NOP instruction
        }

        data
    }

    #[test]
    fn test_parse_headers_valid_pe() {
        let pe_data = create_minimal_pe();
        let result = PE::parse_headers(&pe_data);
        assert!(result.is_ok());
        let (dos_header, nt_header) = result.ok().unwrap();
        let e_magic = unsafe { std::ptr::read_unaligned(&dos_header.e_magic) };
        let e_lfanew = dos_header.e_lfanew;
        let signature = unsafe { std::ptr::read_unaligned(&nt_header.Signature) };
        let num_sections =
            unsafe { std::ptr::read_unaligned(&nt_header.FileHeader.NumberOfSections) };
        let magic = unsafe { std::ptr::read_unaligned(&nt_header.OptionalHeader.Magic.0) };
        assert_eq!(e_magic, 0x5A4D); // MZ
        assert_eq!(e_lfanew, 0x80);
        assert_eq!(signature, 0x4550); // PE\0\0
        assert_eq!(num_sections, 1);
        assert_eq!(magic, 0x20B); // PE32+
    }

    #[test]
    fn test_parse_headers_invalid_dos_magic() {
        let mut pe_data = create_minimal_pe();
        pe_data[0] = 0x00;
        pe_data[1] = 0x00;
        let result = PE::parse_headers(&pe_data);
        assert!(result.is_err());
        let error = result.err().unwrap();
        assert!(error.to_string().contains("Invalid DOS header"));
    }

    #[test]
    fn test_parse_headers_invalid_nt_magic() {
        let mut pe_data = create_minimal_pe();
        pe_data[0x80] = 0x00;
        pe_data[0x81] = 0x00;
        pe_data[0x82] = 0x00;
        pe_data[0x83] = 0x00;
        let result = PE::parse_headers(&pe_data);
        assert!(result.is_err());
        let error = result.err().unwrap();
        assert!(error.to_string().contains("Invalid NT header"));
    }

    #[test]
    fn test_parse_headers_empty_data() {
        let empty_data = Vec::new();
        let result = PE::parse_headers(&empty_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_headers_too_small_data() {
        let small_data = vec![0x4D, 0x5A];
        let result = PE::parse_headers(&small_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_valid_pe() {
        let pe_data = create_minimal_pe();
        let result = PE::load(pe_data);

        assert!(result.is_ok());
        let pe = result.unwrap();

        assert_eq!(pe.dos_header.e_magic, 0x5A4D);
        assert_eq!(pe.nt_header.Signature, 0x4550);
        assert_eq!(pe.nt_header.FileHeader.NumberOfSections, 1);
    }

    #[test]
    fn test_load_invalid_pe() {
        let invalid_data = vec![0x00; 100];
        let result = PE::load(invalid_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_into_memory() {
        let pe_data = create_minimal_pe();
        let pe = PE::load(pe_data).unwrap();

        let result = pe.load_into_memory();
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_valid_pe() {
        let pe_data = create_minimal_pe();
        let result = PE::execute(pe_data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_invalid_pe() {
        let invalid_data = vec![0x00; 100];
        let result = PE::execute(invalid_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_pe_structure_fields() {
        let pe_data = create_minimal_pe();
        let pe = PE::load(pe_data).unwrap();

        // Test that we can access the headers
        assert_eq!(pe.dos_header.e_magic, 0x5A4D);
        assert_eq!(pe.nt_header.Signature, 0x4550);
        assert_eq!(pe.nt_header.OptionalHeader.SizeOfImage, 0x3000);
        assert_eq!(pe.nt_header.OptionalHeader.SizeOfHeaders, 0x200);
    }

    #[test]
    fn test_section_loading() {
        let pe_data = create_minimal_pe();
        let pe = PE::load(pe_data).unwrap();

        // Test that sections are properly parsed
        let nt_header_offset = pe.dos_header.e_lfanew as usize;
        let first_section_offset = unsafe {
            pe.data
                .as_ptr()
                .add(nt_header_offset + size_of::<IMAGE_NT_HEADERS64>())
        } as *const IMAGE_SECTION_HEADER;

        let section = unsafe { &*first_section_offset };

        // Check section properties
        assert_eq!(section.VirtualAddress, 0x1000);
        assert_eq!(section.SizeOfRawData, 0x200);
        assert_eq!(section.PointerToRawData, 0x200);
        assert_eq!(section.Characteristics.0, 0x60000020);
    }
}
