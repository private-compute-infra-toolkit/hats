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

use crate::request_handler::RequestHandler;
use crate::service::Service;
use dynamic_policy_manager::DynamicPolicyManager;
use key_fetcher::KeyFetcher;
use std::sync::Arc;

/// Export Trusted TVS library to C++ code.
///
/// The entry point is NewService() function, which user should call to obtain
/// a Service object before processing client's requests.
/// The user need to pass a unique pointer to `KeyFetcherWrapper`, appraisal
/// policies serialized as binary and flags to determine whether to check
/// signatures on appraisal policies and whether or not to accept insecure
/// policies i.e. allowing self-signed attestation reports (from non CVMs).
/// Upon receiving a request, the client should call Service::create_request_handler()
/// to process all requests from a session.

#[cxx::bridge(namespace = "privacy_sandbox::tvs::trusted")]
mod ffi {

    extern "C++" {
        include!("tvs/key_fetcher_wrapper/key-fetcher-wrapper.h");
        type KeyFetcherWrapper = key_fetcher::ffi::KeyFetcherWrapper;

        include!("tvs/appraisal_policies/dynamic_policy_manager/policy-fetcher-wrapper.h");
        type PolicyFetcherWrapper = dynamic_policy_manager::ffi::PolicyFetcherWrapper;
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

        #[cxx_name = "NewService"]
        fn new_service_with_policy_fetcher(
            key_fetcher_wrapper: UniquePtr<KeyFetcherWrapper>,
            policy_fetcher_wrapper: UniquePtr<PolicyFetcherWrapper>,
            enable_policy_signature: bool,
            accept_insecure_policies: bool,
        ) -> Result<Box<Service>>;

        #[cxx_name = "CreateRequestHandler"]
        unsafe fn create_request_handler(
            self: &Service,
            time_milis: i64,
            user: &str,
        ) -> Box<RequestHandler>;

        type RequestHandler;
        #[cxx_name = "VerifyReport"]
        fn verify_report(self: &mut RequestHandler, request: &[u8]) -> Result<Vec<u8>>;

        #[cxx_name = "IsTerminated"]
        fn is_terminated(self: &RequestHandler) -> bool;
    }
}

/// Create a new service object with pre-fetched policies.
pub fn new_service(
    key_fetcher_wrapper: cxx::UniquePtr<ffi::KeyFetcherWrapper>,
    policies: &[u8],
    enable_policy_signature: bool,
    accept_insecure_policies: bool,
) -> anyhow::Result<Box<Service>> {
    // Intentionally ignore event logger initialization error.
    let _ = env_logger::try_init();
    let key_fetcher = Arc::new(KeyFetcher::new(key_fetcher_wrapper));
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

/// Create a new service object with dynamic policy fetching enabled.
/// a policy fetcher is passed to the service.
pub fn new_service_with_policy_fetcher(
    key_fetcher_wrapper: cxx::UniquePtr<ffi::KeyFetcherWrapper>,
    policy_fetcher_wrapper: cxx::UniquePtr<ffi::PolicyFetcherWrapper>,
    enable_policy_signature: bool,
    accept_insecure_policies: bool,
) -> anyhow::Result<Box<Service>> {
    // Intentionally ignore event logger initialization error.
    let _ = env_logger::try_init();
    let key_fetcher = Arc::new(KeyFetcher::new(key_fetcher_wrapper));
    let dynamic_policy_manager = Arc::new(DynamicPolicyManager::new(
        policy_fetcher_wrapper,
        enable_policy_signature,
        accept_insecure_policies,
    ));
    let service = Service::new_with_evidence_validator(key_fetcher, dynamic_policy_manager);
    match service {
        Ok(service) => Ok(Box::new(service)),
        Err(err) => Err(err),
    }
}
