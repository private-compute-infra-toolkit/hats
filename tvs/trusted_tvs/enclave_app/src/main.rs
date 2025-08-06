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
#![no_main]
#![feature(alloc_error_handler)]

/// TVS enclave main program.
///
/// The binary runs TVS enclave service in a non_std environment e.g. Oak's
/// restricted kernel.
/// The binary exports a number of RPCs over Microrpc to service client's
/// requests proxied through the untrusted code (launcher).
extern crate alloc;
use alloc::boxed::Box;
use oak_restricted_kernel_sdk::{
    channel::{start_blocking_server, FileDescriptorChannel},
    entrypoint,
    utils::samplestore::StaticSampleStore,
};
use trusted_tvs_enclave::enclave_service::EnclaveService;
use tvs_enclave::proto::pcit::tvs::TvsEnclaveServer;

#[entrypoint]
fn start_server() -> ! {
    let enclave_service = EnclaveService::new().expect("Failed to create TrustedTvs service");
    let server = TvsEnclaveServer::new(enclave_service);
    let mut invocation_stats =
        StaticSampleStore::<1000>::new().expect("failed to create StaticSampleStore");

    log::info!("Starting TVS...");
    start_blocking_server(
        Box::<FileDescriptorChannel>::default(),
        server,
        &mut invocation_stats,
    )
    .expect("server encountered an unrecoverable error");
}
