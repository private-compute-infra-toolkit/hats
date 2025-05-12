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
use measure::{calc_launch_digest, types::SevMode, vcpu_types::CpuType};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;
use tar::Archive;
use tempfile::TempDir;
use zerocopy::AsBytes;

#[derive(Parser)]
struct Args {
    #[arg(long, required = true)]
    system_bundle_path: String,
    #[arg(long, required = true)]
    ram_size_kb: usize,
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = Args::parse();

    let system_bundle = unpack_system_bundle(&args.system_bundle_path)?;

    let stage0_sha384 = stage0_measurement(&system_bundle.path().join("stage0_bin"))?;
    let (kernel_image_sha256, kernel_setup_data_sha256) =
        kernel_measurements(&system_bundle.path().join("kernel_bin"))?;
    let init_ram_fs_sha256 = sha256_for_file(&system_bundle.path().join("initrd.cpio.xz"))?;
    let memory_map_sha256 = memory_map(args.ram_size_kb)?;
    let system_image_sha256 = sha256_for_file(&system_bundle.path().join("system.tar.xz"))?;
    println!("stage0_sha384: {}", hex::encode(stage0_sha384));
    println!("kernel_image_sha256: {}", hex::encode(kernel_image_sha256));
    println!(
        "kernel_set_data_sha256: {}",
        hex::encode(kernel_setup_data_sha256)
    );
    println!("init_ram_fs_sha256: {}", hex::encode(init_ram_fs_sha256));
    println!("memory_map_sha256: {}", hex::encode(memory_map_sha256));
    println!("system_image_sha256: {}", hex::encode(system_image_sha256));

    Ok(())
}

fn unpack_system_bundle(file_name: &str) -> anyhow::Result<TempDir> {
    let file = File::open(file_name)?;
    let mut archive = Archive::new(file);
    let tmp_dir = TempDir::new()?;
    archive.unpack(&tmp_dir)?;

    Ok(tmp_dir)
}

fn stage0_measurement(file_name: &Path) -> anyhow::Result<Vec<u8>> {
    let digest = calc_launch_digest(
        SevMode::SevSnp,
        /*vCPU=*/ 4,
        CpuType::EpycMilan,
        file_name,
        /*kernel_path=*/ None,
        /*initrd_path=*/ None,
        /*append_path=*/ None,
    )?;
    Ok(digest.to_vec())
}

fn kernel_measurements(file_name: &PathBuf) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
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

fn sha256_for_file(file_name: &PathBuf) -> anyhow::Result<Vec<u8>> {
    let mut file = File::open(file_name)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    Ok(Sha256::digest(&contents[..]).to_vec())
}

// `E820Table` and `BootE820Entry` are cloned with minor modification from
// https://github.com/project-oak/oak/blob/55607dd8e075bca3607b616efca041a16bd1dedf/oak_linux_boot_params/src/lib.rs

const RAM: u32 = 1;
const RESERVED: u32 = 2;
const ACPI: u32 = 3;

#[repr(C, packed)]
#[derive(AsBytes, Debug, Copy, Clone)]
struct BootE820Entry {
    addr: usize,
    size: usize,
    type_: u32,
}

impl BootE820Entry {
    fn addr(&self) -> usize {
        self.addr
    }
    fn end(&self) -> usize {
        self.addr + self.size
    }

    fn set_addr(&mut self, addr: usize) {
        self.addr = addr;
    }

    fn set_size(&mut self, size: usize) {
        self.size = size;
    }

    fn entry_type(&self) -> u32 {
        self.type_
    }
}

struct E820Table {
    e820_table: [BootE820Entry; 128usize],
    e820_entries: usize,
}

impl E820Table {
    // The methods in this implementation are cloned with minor modification from
    // https://github.com/project-oak/oak/blob/55607dd8e075bca3607b616efca041a16bd1dedf/stage0/src/zero_page.rs
    pub(crate) fn insert_e820_entry(&mut self, entry: BootE820Entry) -> anyhow::Result<()> {
        let mut index = (0..(self.e820_entries))
            .find(|i| entry.addr() <= self.e820_table[*i].addr())
            .unwrap_or(self.e820_entries);
        // Check whether the new entry overlaps with the previous entry.
        if index > 0 && self.e820_table[index - 1].end() >= entry.addr() {
            let mut overlapping = self.e820_table[index - 1];
            if overlapping.entry_type() == entry.entry_type() {
                // Merge the entry with the previous one.
                if overlapping.end() < entry.end() {
                    overlapping.set_size(entry.end() - overlapping.addr());
                    // Copy the modified overlapping entry back.
                    self.e820_table[index - 1] = overlapping;
                }
                index -= 1;
            } else {
                if overlapping.end() > entry.end() {
                    // Split the overlapping range.
                    self.insert_at(
                        BootE820Entry {
                            addr: entry.end(),
                            size: overlapping.end() - entry.end(),
                            type_: overlapping.entry_type(),
                        },
                        index,
                    )?;
                }

                // Trim the previous one to remove the overlap.
                overlapping.set_size(entry.addr() - overlapping.addr());
                self.insert_at(entry, index)?;
                // Copy the modified overlapping entry back.
                self.e820_table[index - 1] = overlapping;
            }
        } else {
            self.insert_at(entry, index)?;
        }

        // Check whether the new entry overlaps with any existing later entries.
        let entry = self.e820_table[index];
        let mut current = index + 1;
        while current < self.e820_entries && entry.end() > self.e820_table[current].addr() {
            if entry.end() >= self.e820_table[current].addr() {
                println!("XXX need to delete");
                self.delete_entry(current);
            } else if entry.entry_type() == self.e820_table[current].entry_type() {
                println!("XXX need to merge");
            } else {
                self.e820_table[current].set_size(self.e820_table[current].end() - entry.end());
                self.e820_table[current].set_addr(entry.end());
                current += 1;
            }
        }

        // Copy the modified entry back.
        self.e820_table[index] = entry;
        Ok(())
    }

    pub(crate) fn ensure_e820_gap(&mut self, start: usize, size: usize) -> anyhow::Result<()> {
        let end = start + size;
        while let Some(index) = (0..self.e820_entries).find(|i| {
            let entry = self.e820_table[*i];
            end > entry.addr() && start < entry.end()
        }) {
            let mut entry = self.e820_table[index];
            if entry.addr() < start && entry.end() > end {
                let new_entry = BootE820Entry {
                    addr: end,
                    size: entry.end() - end,
                    type_: entry.entry_type(),
                };
                entry.set_size(start - entry.addr());
                self.e820_table[index] = entry;
                self.insert_e820_entry(new_entry)?;
            } else if entry.addr() >= start && entry.end() <= end {
                // The entry fits in the gap.
                self.delete_entry(index);
            } else if entry.addr() < start {
                // The entry overlaps with the start of the gap.
                entry.set_size(start - entry.addr());
                self.e820_table[index] = entry;
            } else {
                // The entry overlaps with the end of the gap.
                entry.set_size(entry.end() - end);
                entry.set_addr(end);
                self.e820_table[index] = entry;
            }
        }
        Ok(())
    }

    fn insert_at(&mut self, entry: BootE820Entry, index: usize) -> anyhow::Result<()> {
        if index > self.e820_entries {
            anyhow::bail!("out of bound insert");
        }
        for i in (index..self.e820_entries).rev() {
            self.e820_table[i + 1] = self.e820_table[i];
        }
        self.e820_table[index] = entry;
        self.e820_entries += 1;
        Ok(())
    }

    fn delete_entry(&mut self, index: usize) {
        if index >= self.e820_entries {
            panic!("out of bounds delete");
        }
        for i in (index + 1)..self.e820_entries {
            self.e820_table[i - 1] = self.e820_table[i];
        }
        self.e820_entries -= 1;
    }

    fn print(&self) {
        if !log::log_enabled!(log::Level::Debug) {
            return;
        }

        for i in 0..self.e820_entries {
            let c = &self.e820_table[i];
            let type_ = if c.type_ == RAM {
                "RAM"
            } else if c.type_ == ACPI {
                "ACPI"
            } else if c.type_ == RESERVED {
                "RESERVED"
            } else {
                "UNKNOWN"
            };
            let size = c.size;
            log::debug!(
                "[{:#018x}-{:#018x}), len: {}, type {type_}",
                c.addr(),
                c.addr() + size,
                size
            );
        }
    }

    fn measure(&self) -> Vec<u8> {
        Sha256::digest(self.e820_table[..self.e820_entries].as_bytes()).to_vec()
    }
}

impl Default for E820Table {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

fn memory_map(memory_size_kb: usize) -> anyhow::Result<Vec<u8>> {
    // We first build the E820 table the way QEMU does before handing it to stage0,
    // then change it the way stage0 deos.

    // Convert memory size to bytes.
    let memory_size_bytes = memory_size_kb * 1024;

    // Build E820 table the way QEMU does.
    let mut e = E820Table::default();

    // QEMU q35 machine split the memory into chunks if it does not fit 4G.
    // See qemu/hw/i386/pc_q35.c.
    if memory_size_bytes >= 0xb0000000 {
        e.insert_e820_entry(BootE820Entry {
            addr: 0x0,
            size: 0x80000000,
            type_: RAM,
        })?;
        e.insert_e820_entry(BootE820Entry {
            addr: 0x100000000,
            size: memory_size_bytes - 0x80000000,
            type_: RAM,
        })?;
    } else {
        e.insert_e820_entry(BootE820Entry {
            addr: 0x0,
            size: memory_size_bytes,
            type_: RAM,
        })?;
    }

    // Add memory for KVM Identity map. See qemu/target/i386/kvm/kvm.c
    const KVM_IDENTITY_BASE: usize = 0xfeffc000;
    const KVM_IDENTITY_SIZE: usize = 0x4000;
    e.insert_e820_entry(BootE820Entry {
        addr: KVM_IDENTITY_BASE,
        size: KVM_IDENTITY_SIZE,
        type_: RESERVED,
    })?;

    // Add HyperTransport memory region if we are running in SEV-SNP.
    // See qemu/hw/i386/pc.c
    const AMD_HT_START: usize = 0xfd00000000;
    const AMD_HT_SIZE: usize = 0x300000000;
    e.insert_e820_entry(BootE820Entry {
        addr: AMD_HT_START,
        size: AMD_HT_SIZE,
        type_: RESERVED,
    })?;

    log::debug!("E820 table before passing it to stage0");
    e.print();

    // Now we build E820 the way QEMU does, modify it the way stage0 does.
    // Add a memory chunk for ACPI table.
    e.insert_e820_entry(BootE820Entry {
        addr: 0x80000,
        size: 0x20000,
        type_: ACPI,
    })?;

    // Stage0 initializes the following memory region to handle legacy scan of
    // SMBIOS range.
    e.insert_e820_entry(BootE820Entry {
        addr: 0xf0000,
        size: 0x10000,
        type_: RESERVED,
    })?;

    // Remove the following region as it's used for VGA and it should not be
    // reported in the table.
    // See https://uefi.org/htmlspecs/ACPI_Spec_6_4_html/15_System_Address_Map_Interfaces/e820-assumptions-and-limitations.html
    // and https://github.com/project-oak/oak/blob/55607dd8e075bca3607b616efca041a16bd1dedf/stage0/src/zero_page.rs#L164
    e.ensure_e820_gap(0xa0000, 0x50000)?;

    log::debug!("E820 table after passing it to stage0");
    e.print();

    Ok(e.measure())
}
