use anyhow::Result;
use crate::loader::PE;

mod loader;

fn main() -> Result<()> {
    let pe = PE::load_from_file("test.exe")?;
    let e_lfanew = pe.dos_header.e_lfanew;
    println!("Offset of NT header: 0x{:x}", e_lfanew);
    println!("Entry point: 0x{:x}", pe.nt_header.OptionalHeader.AddressOfEntryPoint);
    Ok(())
}