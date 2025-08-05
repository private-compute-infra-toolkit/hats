// Copyright 2024 Google LLC
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

#![no_std]

/// Traits used by the trusted TVS code.
///
/// The client can customize TVS by implementing traits and pass them to TVS.
/// The crate provides two traits:
/// 1.  Keyprovider: used by TVS to provision the handshake keys and to fetch
///     client authentication keys and secrets to be returned upon successful
///     attestation.
/// 2.  EvidenceValidator: validate attestation evidence against a given
///     measurements (appraisal policies).
extern crate alloc;

#[cfg(feature = "dynamic_attestation")]
pub use binary_store::BinaryStore;
pub use evidence_validator::EvidenceValidator;
pub use key_provider::KeyProvider;

pub mod binary_store;
pub mod evidence_validator;
pub mod key_provider;

#[cfg(test)]
mod tests {
    // Use `super::*` to bring all the public items from this crate
    // (like your BinaryStore trait) into the test's scope.
    use super::*;
    use alloc::string::String;
    use alloc::vec::Vec;
    use hashbrown::HashMap;

    #[cfg(feature = "dynamic_attestation")]
    struct TestBinaryStore {
        // HashMap for dummy OVMF binaries for testing
        store: HashMap<String, Vec<u8>>,
    }

    #[cfg(feature = "dynamic_attestation")]
    impl BinaryStore for TestBinaryStore {
        fn get_ovmf_binary(&self, hash_hex: &str) -> Option<&[u8]> {
            self.store.get(hash_hex).map(|v| v.as_slice())
        }
    }

    #[test]
    #[cfg(feature = "dynamic_attestation")]
    fn test_binary_store_trait() {
        let mut test_store = TestBinaryStore {
            store: HashMap::new(),
        };

        // Define a known hash and some dummy binary data.
        let known_hash = "decbaf118183e601ef943de7ce6be956571acdf8dd6cbf357bb1da43b0e9226dc6d2735ae63e6f07a1ebf2728ce19f8d";
        let binary_data = b"This is a fake OVMF binary for testing.";

        test_store
            .store
            .insert(known_hash.to_string(), binary_data.to_vec());

        // successful lookup
        let retrieved_data = test_store.get_ovmf_binary(known_hash);
        assert!(
            retrieved_data.is_some(),
            "Should find data for a known hash"
        );
        assert_eq!(
            retrieved_data.unwrap(),
            binary_data,
            "Retrieved data should match the original"
        );

        // failed lookup
        let missing_data = test_store.get_ovmf_binary("non_existent_hash");
        assert!(
            missing_data.is_none(),
            "Should return None for an unknown hash"
        );
    }
}
