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

#![cfg_attr(feature = "no_std", no_std)]

/// The crate exports a number of module to build tee verification service.
///
/// Trusted TVS can be used in C++ or Rust code, or can be used in Oak's
/// restricted kernel (no_std environment). For Oak's restricted kernel the
/// library implements TvsEnclave RPC service and export it over MicroRpc.
///
/// The crate export the following modules:
///
/// 1. service: public interface to use the crate. Clients use this crate to
///    create a Service object that owns key materials, policies and means to
///    fetch user secrets.
/// 2. request_handler: an object to handle a single attestation session.
///    The user obtain a handler for every request from *service*.
/// 3. interface: provide an interface to C++ code to use the crate.
///
/// The available feature flags are:
///
/// 1. no_std: running the crate in a non\_std environment e.g. Oak's restricted
///    kernel.
/// 2. default: enable creating crate to be used in Rust code and export the
///    crate to C++.
/// 3. enclave: export TvsEnclave RPC service over MicroRpc to be used in Oak's
///    restricted kernel.

#[cfg(feature = "enclave")]
pub mod enclave_service;
#[cfg(feature = "default")]
pub mod interface;
pub mod request_handler;
#[cfg(feature = "default")]
pub mod service;
