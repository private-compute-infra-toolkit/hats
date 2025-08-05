// Copyright 2024 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/// A trait for a key-value store that provides raw stage0/OVMF binary blobs.
///
/// This trait acts as an abstraction between the policy verification logic and the
/// data source for OVMF binaries, allowing for different implementations for
/// production (e.g., Spanner) and testing (e.g., an in-memory HashMap).
#[cfg(feature = "dynamic_attestation")]
pub trait BinaryStore {
    /// This function fetches a raw OVMF binary based on its content hash.
    /// This function takes the following parameters:
    /// `hash_hex`: The SHA-256 hash of the binary, represented as a hex string.
    ///
    /// The function returns a `Option<&[u8]>` containing a reference to the raw binary data if found,
    /// or `None` if no binary matches the given hash.
    fn get_ovmf_binary(&self, hash_hex: &str) -> Option<&[u8]>;
}
