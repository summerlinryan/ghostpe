#![allow(dead_code)]
use crate::loader::PE;
use anyhow::Result;

mod loader;

fn main() -> Result<()> {
    PE::execute_from_file("test.exe")
}