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

use request_handler::{new_request_handler, new_request_handler_with_second_key, RequestHandler};

pub mod request_handler;
pub mod proto {
    pub mod privacy_sandbox {
        pub mod tvs {
            include!(concat!(env!("OUT_DIR"), "/privacy_sandbox.tvs.rs"));
        }
    }
}

// Export RequestHandler and it's methods to C++.
#[cxx::bridge(namespace = "privacy_sandbox::tvs")]
mod ffi {
    extern "Rust" {
        type RequestHandler;

        #[cxx_name = "NewRequestHandler"]
        fn new_request_handler(
            time_milis: i64,
            primary_private_key: &[u8],
            policy: &[u8],
            user: &str,
            enable_policy_signature: bool,
            accept_insecure_policies: bool,
        ) -> Result<Box<RequestHandler>>;

        #[cxx_name = "NewRequestHandler"]
        fn new_request_handler_with_second_key(
            time_milis: i64,
            primary_private_key: &[u8],
            secondary_private_key: &[u8],
            policy: &[u8],
            user: &str,
            enable_policy_signature: bool,
            accept_insecure_policies: bool,
        ) -> Result<Box<RequestHandler>>;

        #[cxx_name = "VerifyReport"]
        fn verify_report(self: &mut RequestHandler, request: &[u8]) -> Result<Vec<u8>>;

        #[cxx_name = "IsTerminated"]
        fn is_terminated(self: &RequestHandler) -> bool;
    }
}
