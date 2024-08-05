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

#[cxx::bridge(namespace = "privacy_sandbox::key_manager")]

mod ffi {
    unsafe extern "C++" {
        include!("key_manager/key-fetcher-wrapper.h");
        fn GetSecret(secret_id: &str) -> Result<Vec<u8>>;
    }
}

pub fn get_secret(secret_id: &str) -> Result<Vec<u8>, String> {
    ffi::GetSecret(secret_id).map_err(|err| format!("error {}", err))
}
