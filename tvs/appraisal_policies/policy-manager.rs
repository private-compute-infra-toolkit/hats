// Copyright 2024 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use oak_proto_rust::oak::attestation::v1::{
    endorsements, reference_values, Endorsements, Evidence, OakContainersEndorsements,
    ReferenceValues, RootLayerEndorsements,
};
use p256::ecdsa::VerifyingKey;

pub struct PolicyManager {
    time_milis: i64,
    appraisal_policies: Vec<ReferenceValues>,
}

impl PolicyManager {
    pub fn new(
        time_milis: i64,
        policies: &[u8],
        enable_policy_signature: bool,
        accept_insecure_policies: bool,
    ) -> Result<Self, String> {
        let appraisal_policies = if enable_policy_signature {
            let policy_verifying_key: VerifyingKey = get_policy_public_key()?;
            policy_signature::decode_and_verify_policies(
                policies,
                vec![policy_verifying_key],
                /*num_pass_required=*/ 1,
            )
        } else {
            policy_signature::decode_and_verify_policies(
                policies,
                /*verifying_keys*/ vec![],
                /*num_pass_required=*/ 0,
            )
        }?;
        verify_policy_tee(&appraisal_policies, accept_insecure_policies)?;
        Ok(Self {
            time_milis,
            appraisal_policies,
        })
    }

    // Check evidence against the appraisal policies.
    pub fn check_evidence(
        &self,
        evidence: &Evidence,
        tee_certificate: &[u8],
    ) -> Result<(), String> {
        let endorsement = create_endorsements(tee_certificate);
        for policy in &self.appraisal_policies {
            match oak_attestation_verification::verifier::verify(
                self.time_milis,
                &evidence,
                &endorsement,
                &policy,
            ) {
                Ok(_) => return Ok(()),
                Err(_) => continue,
            };
        }
        Err("Failed to verify report. No matching appraisal policy found".to_string())
    }
}

// When running in secure mode, reject policies that doesn't require SEV-SNP.
fn verify_policy_tee(
    appraisal_policies: &[ReferenceValues],
    accept_insecure_policies: bool,
) -> Result<(), String> {
    if accept_insecure_policies {
        return Ok(());
    }
    for policy in appraisal_policies {
        let root_layer = match policy.r#type.as_ref() {
            Some(reference_values::Type::OakRestrictedKernel(r)) => {
                r.root_layer.as_ref().ok_or("No root layer".to_string())
            }
            Some(reference_values::Type::OakContainers(r)) => {
                r.root_layer.as_ref().ok_or("No root layer".to_string())
            }
            Some(reference_values::Type::Cb(r)) => {
                r.root_layer.as_ref().ok_or("No root layer".to_string())
            }
            None => Err("Cannot accept a policy without a type".to_string()),
        }?;
        if root_layer.insecure.is_some() {
            return Err("Cannot accept insecure policies".to_string());
        };
        if root_layer.intel_tdx.is_some() {
            return Err("Cannot accept intel TDX policies".to_string());
        };
        if root_layer.amd_sev.is_none() {
            return Err("Cannot accept non AMD SEV SNP  policies".to_string());
        }
    }
    Ok(())
}

// TODO(b/358413924): Actually fetch key
fn get_policy_public_key() -> Result<VerifyingKey, String> {
    Ok(VerifyingKey::from_sec1_bytes(
        &hex::decode("048fa2c25d3d3368b23f7877c9ac84866f440f9dd7a94e7ca5440ef1bc611f77db2940cca2233d06c9cfbf503ee73fdf5cf1f4c637f376bb7daaf637faf05656e4")
        .map_err(|_| "Failed to decode policy PK hex")?
    )
    .map_err(|_| "Failed to parse policy PK")?)
}

fn create_endorsements(tee_certificate: &[u8]) -> Endorsements {
    let root_layer = RootLayerEndorsements {
        tee_certificate: tee_certificate.to_vec(),
        stage0: None,
    };
    let ends = OakContainersEndorsements {
        root_layer: Some(root_layer),
        container_layer: None,
        kernel_layer: None,
        system_layer: None,
    };
    Endorsements {
        r#type: Some(endorsements::Type::OakContainers(ends)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use policy_signature::proto::privacy_sandbox::tvs::{
        appraisal_policies::SignedAppraisalPolicy, AppraisalPolicies,
    };
    use prost::Message;

    fn default_appraisal_policicies() -> Vec<u8> {
        let signed_policy = SignedAppraisalPolicy::decode(
            &include_bytes!("../test_data/on-perm-reference.binarypb")[..],
        )
        .unwrap();
        let policies = AppraisalPolicies {
            signed_policy: vec![signed_policy],
            policies: vec![],
        };
        let mut buf: Vec<u8> = Vec::with_capacity(1024);
        policies.encode(&mut buf).unwrap();
        buf
    }

    fn insecure_appraisal_policies() -> Vec<u8> {
        let signed_policy = SignedAppraisalPolicy::decode(
            &include_bytes!("../test_data/insecure-reference.binarypb")[..],
        )
        .unwrap();
        let policies = AppraisalPolicies {
            signed_policy: vec![signed_policy],
            policies: vec![],
        };
        let mut buf: Vec<u8> = Vec::with_capacity(1024);
        policies.encode(&mut buf).unwrap();
        buf
    }

    fn get_genoa_vcek() -> Vec<u8> {
        include_bytes!("../test_data/vcek_genoa.crt").to_vec()
    }
    fn get_good_evidence() -> oak_proto_rust::oak::attestation::v1::Evidence {
        oak_proto_rust::oak::attestation::v1::Evidence::decode(
            include_bytes!("../test_data/good_evidence.binarypb").as_slice(),
        )
        .expect("could not decode evidence")
    }

    fn get_bad_evidence() -> oak_proto_rust::oak::attestation::v1::Evidence {
        oak_proto_rust::oak::attestation::v1::Evidence::decode(
            include_bytes!("../test_data/bad_evidence.binarypb").as_slice(),
        )
        .expect("could not decode evidence")
    }

    const NOW_UTC_MILLIS: i64 = 1698829200000;

    #[test]
    fn check_evidence_successful() {
        let policy_manager = PolicyManager::new(
            NOW_UTC_MILLIS,
            &default_appraisal_policicies(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        )
        .unwrap();
        assert!(policy_manager
            .check_evidence(&get_good_evidence(), &get_genoa_vcek())
            .is_ok());
    }

    #[test]
    fn check_evidence_error() {
        let policy_manager = PolicyManager::new(
            NOW_UTC_MILLIS,
            &default_appraisal_policicies(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        )
        .unwrap();
        match policy_manager.check_evidence(&get_bad_evidence(), &get_genoa_vcek()) {
            Ok(_) => assert!(false, "check_evidence() should fail."),
            Err(e) => assert_eq!(
                e,
                "Failed to verify report. No matching appraisal policy found"
            ),
        }
    }

    #[test]
    fn policy_manager_creation_error() {
        match PolicyManager::new(
            NOW_UTC_MILLIS,
            /*policies=*/ &[1, 2, 3],
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        ) {
            Ok(_) => assert!(false, "PolicyManager::new() should fail."),
            Err(e) => assert_eq!(e, "Failed to decode (serialize) appraisal policy."),
        }

        match PolicyManager::new(
            NOW_UTC_MILLIS,
            &insecure_appraisal_policies(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        ) {
            Ok(_) => assert!(false, "PolicyManager::new() should fail."),
            Err(e) => assert_eq!(e, "Cannot accept insecure policies",),
        }
    }
}
