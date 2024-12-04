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

use oak_proto_rust::oak::attestation::v1::Evidence;

/// Trait to validate attestation evidence.
pub trait EvidenceValidator: Sync + Send {
    /// Check evidence against the appraisal policies.
    /// The function takes the following parameters:
    /// time_milis: the current time to be passed to Oak's attestation
    /// verification library. The time is currently ignored in the verification
    /// library.
    /// evidence: an event log or DICE chain that contains the CVM full stack
    /// measurements.
    /// tee_certificate: certificate issued by the hardware vendor used to
    /// sign the root attestation report. The certificate is used to validate
    /// the root layer signature. The certificate is validated against a cert
    /// chain issued by the vendor.
    fn check_evidence(
        &self,
        time_milis: i64,
        evidence: &Evidence,
        tee_certificate: &[u8],
    ) -> anyhow::Result<()>;
}
