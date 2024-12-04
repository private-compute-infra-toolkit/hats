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

use anyhow::Context;
use oak_proto_rust::oak::attestation::v1::extracted_evidence::EvidenceValues::OakContainers;
use oak_proto_rust::oak::attestation::v1::Evidence;
use policy_manager::PolicyManager;
use trusted_tvs_types::EvidenceValidator;

/// Validate measurements against appraisal policies from storage.
///
/// The crate takes C++ PolicyFetcherWrapper to retrieve policies
/// from storage (local or Spanner). The crate extracts the application
/// layer digest, searches for policies that matches the digest, and then it
/// evaluates evidence against them using PolicyManager module from
/// policy_manager crate.
/// The crate implements EvidenceValidator trait to make it usable to
/// TrustedTvs.

/// Provide Rust interface to `tvs/appraisal_policies/policy-fetcher.h`.
#[cxx::bridge(namespace = "privacy_sandbox::tvs::trusted")]
pub mod ffi {
    struct VecU8Result {
        value: Vec<u8>,
        error: String,
    }
    unsafe extern "C++" {
        include!("tvs/appraisal_policies/dynamic_policy_manager/policy-fetcher-wrapper.h");

        type PolicyFetcherWrapper;

        #[rust_name = "get_latest_n_policies_for_digest"]
        fn GetLatestNPoliciesForDigest(&self, application_digest: &[u8], n: i32) -> VecU8Result;
    }
    // Explicitly request UniquePtr instantiation for PolicyFetcherWrapper.
    impl UniquePtr<PolicyFetcherWrapper> {}
}

// Tell rust that `KeyFetcherWrapper` is thread-safe.
unsafe impl Sync for ffi::PolicyFetcherWrapper {}
unsafe impl Send for ffi::PolicyFetcherWrapper {}

/// Encapsulates unique pointer of PolicyFetcherWrapper and implement
/// EvidenceValidator trait required for trusted TVS.
pub struct DynamicPolicyManager {
    policy_fetcher_wrapper: cxx::UniquePtr<ffi::PolicyFetcherWrapper>,
    enable_policy_signature: bool,
    accept_insecure_policies: bool,
}

impl DynamicPolicyManager {
    /// Create a new dynamic policy manager object. The function takes the
    /// following parameters:
    /// policy_fetcher_wrapper: unique pointer to C++ PolicyFetcherWrapper
    /// object.
    /// enable_policy_signature: whether or not to check signature on the
    /// policies.
    /// accept_insecure_policies: whether or not to accept policies allowing
    /// measurement from non-CVM i.e. self signed reports.
    pub fn new(
        policy_fetcher_wrapper: cxx::UniquePtr<ffi::PolicyFetcherWrapper>,
        enable_policy_signature: bool,
        accept_insecure_policies: bool,
    ) -> Self {
        Self {
            policy_fetcher_wrapper,
            enable_policy_signature,
            accept_insecure_policies,
        }
    }
}

const NUM_OF_POLICIES: i32 = 10;

impl EvidenceValidator for DynamicPolicyManager {
    /// Check evidence against the appraisal policies.
    /// The method extracts `container_binary_sha256` field from the evidence
    /// proto and searches the underlying storage for policies matching the
    /// the digest. It then evaluates the measurements against the policies
    /// serially.
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
    ) -> anyhow::Result<()> {
        let application_digest = application_digest_from_evidence(evidence)?;
        let policies = self
            .policy_fetcher_wrapper
            .get_latest_n_policies_for_digest(&application_digest, /*n=*/ NUM_OF_POLICIES);
        if !policies.error.is_empty() {
            return Err(anyhow::anyhow!(policies.error));
        }
        let policy_manager = PolicyManager::new_with_policies(
            &policies.value,
            self.enable_policy_signature,
            self.accept_insecure_policies,
        )?;
        policy_manager.check_evidence(time_milis, evidence, tee_certificate)
    }
}

fn application_digest_from_evidence(evidence: &Evidence) -> anyhow::Result<Vec<u8>> {
    let extracted_evidence = oak_attestation_verification::extract::extract_evidence(evidence)
        .context("extracting evidence")?;
    let oak_containers_layer = match extracted_evidence.evidence_values {
        Some(OakContainers(oak_containers)) => oak_containers.container_layer,
        Some(_) => anyhow::bail!("Evidence does not have OakContainers field"),
        None => anyhow::bail!("Evidence does not have OakContainers field"),
    };
    let Some(oak_containers_layer) = oak_containers_layer else {
        anyhow::bail!("Evidence does not have oak containers layer field");
    };

    let Some(bundle) = oak_containers_layer.bundle else {
        anyhow::bail!("Evidence does not contain application bundle field");
    };
    Ok(bundle.sha2_256)
}
