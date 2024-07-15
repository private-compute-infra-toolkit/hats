use anyhow::{anyhow, Context, Result};
use curl::easy::Easy;
use sev::firmware::host::*;
use std::arch::x86_64;

#[cxx::bridge(namespace = "privacy_sandbox::launcher")]
mod ffi {
    extern "Rust" {
        pub fn get_vcek() -> Result<Vec<u8>>;
    }
}

// Get the SEV generation of the processor currently running on the machine.
// To do this, we execute a CPUID (label 0x80000001) and read the EAX
// register as an array of bytes (each byte representing 8 bits of a 32-bit
// value, thus the array is 4 bytes long). The formatting for these values is
// as follows:
//
//  Base model:         bits 4:7
//  Base family:        bits 8:11
//  Extended model:     bits 16:19
//  Extended family:    bits 20:27
//
// Extract the bit values from the array, and use them to calculate the MODEL
// and FAMILY of the processor.
//
// The family calculation is as follows:
//
//      FAMILY = Base family + Extended family
//
// The model calculation is a follows:
//
//      MODEL = Base model | (Extended model << 4)
//
// Compare these values with the models and families of known processor generations to
// determine which generation the current processor is a part of.
fn get_hardware_model() -> Result<String> {
    let cpuid = unsafe { x86_64::__cpuid(0x8000_0001) };

    // Bits 31:28 are used to differentiate between Bergamo and Siena machines.
    let socket = (cpuid.ebx & 0xF0000000u32) >> 0x1C;

    let bytes: Vec<u8> = cpuid.eax.to_le_bytes().to_vec();

    let base_model = (bytes[0] & 0xF0) >> 4;
    let base_family = bytes[1] & 0x0F;

    let ext_model = bytes[2] & 0x0F;

    let ext_family = {
        let low = (bytes[2] & 0xF0) >> 4;
        let high = (bytes[3] & 0x0F) << 4;

        low | high
    };

    let model = (ext_model << 4) | base_model;
    let family = base_family + ext_family;

    match family {
        0x19 => match model {
            0x0..=0xF => Ok(String::from("Milan")),
            // Genoa, Bergamo, Siena maps to Genoa for purpose of fetching VCEK from AMD KDS.
            0x10..=0x1F => Ok(String::from("Genoa")),
            0xA0..=0xAF => match socket {
                0x4 => Ok(String::from("Genoa")), // Bergamo
                0x8 => Ok(String::from("Genoa")), // Siena
                _ => Err(anyhow!("processor is not of a known SEV-SNP generation")),
            },
            _ => Err(anyhow!("processor is not of a known SEV-SNP model")),
        },
        _ => Err(anyhow!("processor is not of a known SEV-SNP family")),
    }
}

fn vcek_url() -> Result<String> {
    let mut firmware = Firmware::open().context("unable to open /dev/sev")?;

    let id = firmware
        .get_identifier()
        .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
        .context("error fetching identifier")?;
    let status = firmware.snp_platform_status()?;
    let model = get_hardware_model()?;

    Ok(format!("https://kdsintf.amd.com/vcek/v1/{}/{}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
                         model, id, status.reported_tcb_version.bootloader,
                         status.reported_tcb_version.tee,
                         status.reported_tcb_version.snp,
                         status.reported_tcb_version.microcode))
}

fn get_vcek_from_url(url: &str) -> Result<Vec<u8>> {
    let mut http_handle = Easy::new();
    let mut buf: Vec<u8> = Vec::new();

    http_handle.url(url)?;
    http_handle.get(true)?;

    let mut transfer = http_handle.transfer();
    transfer.write_function(|data| {
        buf.extend_from_slice(data);
        Ok(data.len())
    })?;

    transfer.perform()?;
    drop(transfer);

    Ok(buf)
}

pub fn get_vcek() -> Result<Vec<u8>> {
    get_vcek_from_url(&vcek_url()?)
}
