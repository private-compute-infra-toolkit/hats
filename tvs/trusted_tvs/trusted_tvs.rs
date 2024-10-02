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

use request_handler::RequestHandler;
use service::{new_service, new_service_with_second_key, Service};

pub mod request_handler;
pub mod service;
pub mod proto {
    pub mod privacy_sandbox {
        pub mod tvs {
            include!(concat!(env!("OUT_DIR"), "/privacy_sandbox.tvs.rs"));
        }
    }
}

#[cxx::bridge(namespace = "privacy_sandbox::tvs::trusted")]
mod ffi {
    extern "Rust" {
        type Service;
        #[cxx_name = "NewService"]
        fn new_service(
            primary_private_key: &[u8],
            policy: &[u8],
            enable_policy_signature: bool,
            accept_insecure_policies: bool,
        ) -> Result<Box<Service>>;

        #[cxx_name = "NewService"]
        fn new_service_with_second_key(
            primary_private_key: &[u8],
            secondary_private_key: &[u8],
            policy: &[u8],
            enable_policy_signature: bool,
            accept_insecure_policies: bool,
        ) -> Result<Box<Service>>;

        #[cxx_name = "CreateRequestHandler"]
        unsafe fn create_request_handler<'a>(
            self: &'a Service,
            time_milis: i64,
            user: &str,
        ) -> Box<RequestHandler<'a>>;

        type RequestHandler<'a>;
        #[cxx_name = "VerifyReport"]
        fn verify_report(self: &mut RequestHandler, request: &[u8]) -> Result<Vec<u8>>;

        #[cxx_name = "IsTerminated"]
        fn is_terminated(self: &RequestHandler) -> bool;
    }
}
