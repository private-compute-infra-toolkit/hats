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

use trusted_tvs_types::KeyProvider;

/// Provide Rust interface to `key_manager/key-fetcher.h` for the trusted TVS.
///
/// In particular, this module provides the following:
/// 1. Foreign function interface (FFI) for
///    `tvs/key_fetcher_wrapper/key-fetcher-wrapper.h` to be used in Rust.
/// 2. Implements KeyProvider trait that the trusted TVS understand.

/// FFI for methods in tvs/key_fetcher_wrapper/key-fetcher-wrapper.h.
#[cxx::bridge(namespace = "privacy_sandbox::tvs::trusted")]
pub mod ffi {
    struct VecU8Result {
        value: Vec<u8>,
        error: String,
    }

    unsafe extern "C++" {
        include!("tvs/key_fetcher_wrapper/key-fetcher-wrapper.h");

        type KeyFetcherWrapper;

        #[rust_name = "get_primary_private_key"]
        fn GetPrimaryPrivateKey(&self) -> VecU8Result;

        #[rust_name = "get_secondary_private_key"]
        fn GetSecondaryPrivateKey(&self) -> VecU8Result;

        #[rust_name = "user_id_for_authentication_key"]
        fn UserIdForAuthenticationKey(&self, public_key: &[u8]) -> VecU8Result;

        #[rust_name = "get_secrets_for_user_id"]
        fn GetSecretsForUserId(&self, user_id: &[u8]) -> VecU8Result;

        // Used for unittests.
        #[rust_name = "create_test_key_fetcher_wrapper"]
        fn CreateTestKeyFetcherWrapper(
            primary_private_key: &[u8],
            secondary_private_key: &[u8],
            user_id: &[u8],
            user_authentication_public_key: &[u8],
            key_id: &[u8],
            secret: &[u8],
            public_key: &[u8],
        ) -> UniquePtr<KeyFetcherWrapper>;
    }
    // Explicitly request UniquePtr instantiation for KeyFetcherWrapper.
    impl UniquePtr<KeyFetcherWrapper> {}
}

// Tell rust that `KeyFetcherWrapper` is thread-safe.
unsafe impl Sync for ffi::KeyFetcherWrapper {}
unsafe impl Send for ffi::KeyFetcherWrapper {}

/// Encapsulates unique pointer of KeyFetcherWrapper and implement KeyProvider
/// trait required for trusted TVS.
pub struct KeyFetcher {
    key_fetcher_wrapper: cxx::UniquePtr<ffi::KeyFetcherWrapper>,
}

impl KeyFetcher {
    pub fn new(key_fetcher_wrapper: cxx::UniquePtr<ffi::KeyFetcherWrapper>) -> Self {
        Self {
            key_fetcher_wrapper,
        }
    }
}

impl KeyProvider for KeyFetcher {
    fn get_primary_private_key(&self) -> anyhow::Result<Vec<u8>> {
        let primary_private_key = self.key_fetcher_wrapper.get_primary_private_key();
        if !primary_private_key.error.is_empty() {
            return Err(anyhow::anyhow!(primary_private_key.error));
        }
        Ok(primary_private_key.value)
    }

    fn get_secondary_private_key(&self) -> Option<anyhow::Result<Vec<u8>>> {
        let secondary_private_key = self.key_fetcher_wrapper.get_secondary_private_key();
        if !secondary_private_key.error.is_empty() {
            return Some(Err(anyhow::anyhow!(secondary_private_key.error)));
        }
        if secondary_private_key.value.is_empty() {
            return None;
        }
        Some(Ok(secondary_private_key.value))
    }

    fn user_id_for_authentication_key(&self, public_key: &[u8]) -> anyhow::Result<Vec<u8>> {
        let user_id = self
            .key_fetcher_wrapper
            .user_id_for_authentication_key(public_key);
        if !user_id.error.is_empty() {
            return Err(anyhow::anyhow!(
                "Unauthenticated, provided public key is not registered: {}",
                user_id.error
            ));
        }
        Ok(user_id.value)
    }

    fn get_secrets_for_user_id(&self, user_id: &[u8]) -> anyhow::Result<Vec<u8>> {
        let secret = self.key_fetcher_wrapper.get_secrets_for_user_id(user_id);
        if !secret.error.is_empty() {
            let user_id_str = std::str::from_utf8(user_id)
                .map_err(|_| anyhow::anyhow!("Failed to get secret for user ID: {:?}", user_id))?;
            return Err(anyhow::anyhow!(
                "Failed to get secret for user ID: {user_id_str}"
            ));
        }
        Ok(secret.value)
    }
}
