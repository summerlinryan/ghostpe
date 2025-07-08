#![allow(dead_code)]
use crate::loader::PE;
use anyhow::Result;
use log::info;

mod loader;

fn main() -> Result<()> {
    env_logger::init();
    info!("Starting PE loader");
    PE::execute_from_file("test.exe")
}
