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

// Define foreign function interface (FFI) to use the C++ KeyFetcherWrapper in
// Rust.

#[cxx::bridge(namespace = "privacy_sandbox::key_manager")]
pub mod ffi {
    unsafe extern "C++" {
        include!("key_manager/key-fetcher-wrapper.h");
        #[rust_name = "get_secret"]
        fn GetSecret(secret_name: &str) -> Result<Vec<u8>>;
        #[rust_name = "user_id_for_authentication_key"]
        fn UserIdForAuthenticationKey(public_key: &[u8]) -> Result<i64>;
        #[rust_name = "get_secret_for_user_id"]
        fn GetSecretForUserId(user_id: i64) -> Result<Vec<u8>>;
        #[rust_name = "register_echo_key_fetcher_for_test"]
        fn RegisterEchoKeyFetcherForTest();
    }
}
