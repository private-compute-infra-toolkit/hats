// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
use crate::shamir_sharing;
use crate::xor_sharing;
use crate::SecretSplit;

/// Export Secret Sharing TVS library to C++ code.
#[cxx::bridge(namespace = "privacy_sandbox::crypto")]
mod ffi {
    extern "Rust" {
        #[cxx_name = "XorSplitSecret"]
        fn xor_split_wrap(secret_bytes: &[u8], numshares: usize) -> Result<Vec<String>>;

        #[cxx_name = "ShamirSplitSecret"]
        fn shamir_split_wrap(
            secret_bytes: &[u8],
            numshares: usize,
            threshold: usize,
        ) -> Result<Vec<String>>;

        #[cxx_name = "XorRecoverSecret"]
        fn xor_recover_wrap(shares_vec: &Vec<String>, numshares: usize) -> Result<Vec<u8>>;

        #[cxx_name = "ShamirRecoverSecret"]
        fn shamir_recover_wrap(
            shares_vec: &Vec<String>,
            numshares: usize,
            threshold: usize,
        ) -> Result<Vec<u8>>;
    }
}

pub fn shamir_split_wrap(
    secret_bytes: &[u8],
    numshares: usize,
    threshold: usize,
) -> Result<Vec<String>, String> {
    let sham = shamir_sharing::ShamirSharing {
        numshares,
        threshold,
        prime: shamir_sharing::get_prime(),
    };
    let shares = sham
        .split(secret_bytes)
        .map_err(|err| format!("Error splitting secret: {:#?}", err))?;
    Ok(shares)
}

pub fn shamir_recover_wrap(
    shares_vec: &Vec<String>,
    numshares: usize,
    threshold: usize,
) -> Result<Vec<u8>, String> {
    let sham = shamir_sharing::ShamirSharing {
        numshares,
        threshold,
        prime: shamir_sharing::get_prime(),
    };

    let mut shares: Vec<&[u8]> = Vec::new();
    for share in shares_vec {
        shares.push(share.as_bytes());
    }
    sham.recover(&shares)
        .map_err(|_| "Error recovering secrets".to_string())
}

pub fn xor_split_wrap(secret_bytes: &[u8], numshares: usize) -> Result<Vec<String>, String> {
    let xor = xor_sharing::XorSharing { numshares };
    let shares = xor
        .split(secret_bytes)
        .map_err(|err| format!("Error splitting secret: {:#?}", err))?;
    Ok(shares)
}

pub fn xor_recover_wrap(shares_vec: &Vec<String>, numshares: usize) -> Result<Vec<u8>, String> {
    let xor = xor_sharing::XorSharing { numshares };

    let mut shares: Vec<&[u8]> = Vec::new();
    for share in shares_vec {
        shares.push(share.as_bytes());
    }
    xor.recover(&shares)
        .map_err(|_| "Error recovering secrets".to_string())
}
