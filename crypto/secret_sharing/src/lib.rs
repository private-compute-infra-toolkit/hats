// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
use anyhow::Result;

/// Trait to split and recover secrets
pub trait SecretSplit {
    /// Splits secret into multiple shares
    /// This function takes the following parameters:
    /// secret_bytes: the secret to split
    fn split(&self, secret_bytes: &[u8]) -> Result<Vec<String>, Error>;
    /// Recovers the secret from multiple shares
    /// This function takes the following parameters:
    /// serialized_shares: list of serialized share splits to use to for recovery
    fn recover(&self, serialized_shares: &[&[u8]]) -> Result<Vec<u8>, Error>;
}

// Do not use cxx:bridge if `noffi` is enabled. This is to avoid
// linking against C++ standard and cxx libraries in pure rust code.
#[cfg(not(feature = "noffi"))]
pub mod interface;
pub mod shamir_sharing;
pub mod xor_sharing;

#[derive(Debug, PartialEq)]
pub enum Error {
    BelowThreshold,
    ThresholdGreaterThanNumShares,
    MustSplitTrust,
    SecretMustBeInRangePrime,
    ImproperCoeffs,
    NotAShareObject,
    MalformedSecret,
    MixedShareType,
    SerializationFailure,
}
