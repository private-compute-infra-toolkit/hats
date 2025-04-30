// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use clap::Parser;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;

#[derive(Parser)]
struct Args {
    #[arg(long, required = true)]
    kernel_file_path: String,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let (kernel_image_sha256, kernel_setup_data_sha256) =
        kernel_measurements(&args.kernel_file_path)?;

    println!("kernel_image_sha256: {}", hex::encode(kernel_image_sha256));
    println!(
        "kernel_set_data_sha256: {}",
        hex::encode(kernel_setup_data_sha256)
    );

    Ok(())
}

fn kernel_measurements(file_name: &str) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let mut file = File::open(file_name)?;

    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    // Linux Kernel layout: https://www.kernel.org/doc/Documentation/x86/boot.txt
    const SETUP_SECTS: usize = 0x1f1;

    if contents.len() < SETUP_SECTS {
        anyhow::bail!("Could not read setup_sects from the header. File is to small");
    }

    let setup_section = if contents[SETUP_SECTS] == 0 {
        // Assume the size is 4.
        4
    } else {
        contents[SETUP_SECTS]
    };
    let setup_section_size = (setup_section + 1) as usize * 512;

    if contents.len() < setup_section_size {
        anyhow::bail!("Failed to parse kernel file. File is smaller than the calculated setup section location.");
    }

    Ok((
        Sha256::digest(&contents[setup_section_size..]).to_vec(),
        Sha256::digest(&contents[..setup_section_size]).to_vec(),
    ))
}
