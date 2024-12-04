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

pub use evidence_validator::EvidenceValidator;
pub use key_provider::KeyProvider;

pub mod evidence_validator;
pub mod key_provider;
