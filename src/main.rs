#![allow(dead_code)]
use crate::loader::PE;
use anyhow::Result;
use log::info;
use std::env;

mod loader;

fn main() -> Result<()> {
    env_logger::init();
    info!("Starting PE loader");

    let args: Vec<String> = env::args().collect();
    let default_path = "test.dll".to_string();
    let file_path = args.get(1).unwrap_or(&default_path);

    info!("Loading PE file: {}", file_path);
    PE::execute_from_file(file_path)
}
