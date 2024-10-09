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

use key_fetcher::KeyFetcher;
use request_handler::RequestHandler;
use service::Service;

pub mod request_handler;
pub mod service;

#[cxx::bridge(namespace = "privacy_sandbox::tvs::trusted")]
mod ffi {

    extern "C++" {
        include!("tvs/trusted_tvs/key-fetcher-wrapper.h");
        type KeyFetcherWrapper = key_fetcher::ffi::KeyFetcherWrapper;
    }

    extern "Rust" {
        type Service;

        #[cxx_name = "NewService"]
        fn new_service(
            key_fetcher_wrapper: UniquePtr<KeyFetcherWrapper>,
            policies: &[u8],
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

fn new_service(
    key_fetcher_wrapper: cxx::UniquePtr<ffi::KeyFetcherWrapper>,
    policies: &[u8],
    enable_policy_signature: bool,
    accept_insecure_policies: bool,
) -> anyhow::Result<Box<Service>> {
    let key_fetcher = KeyFetcher::new(key_fetcher_wrapper);
    let service = Service::new(
        key_fetcher,
        policies,
        enable_policy_signature,
        accept_insecure_policies,
    );
    match service {
        Ok(service) => Ok(Box::new(service)),
        Err(err) => Err(err),
    }
}
