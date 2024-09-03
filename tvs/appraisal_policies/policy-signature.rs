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

use crate::proto::privacy_sandbox::tvs::{
    appraisal_policies::Signature as SignatureWrapper, appraisal_policies::SignedAppraisalPolicy,
    AppraisalPolicies,
};
use p256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
use prost::Message;

pub mod proto {
    pub mod privacy_sandbox {
        pub mod tvs {
            include!(concat!(env!("OUT_DIR"), "/privacy_sandbox.tvs.rs"));
        }
    }
}

pub fn decode_and_verify_policies(
    policies: &[u8],
    verifying_keys: Vec<VerifyingKey>,
    num_pass_required: usize,
) -> Result<Vec<oak_proto_rust::oak::attestation::v1::ReferenceValues>, String> {
    if num_pass_required > verifying_keys.len() {
        return Err("Requesting more signature passes than provided verifying keys".to_string());
    }
    AppraisalPolicies::decode(policies)
        .map_err(|_| "Failed to decode (serialize) appraisal policy.".to_string())?
        .signed_policy
        .into_iter()
        .map(|policy| verify_policy_signature(&policy, &verifying_keys, num_pass_required))
        .collect()
}

// TODO(b/358413924): Support signature id, multiple signatures
pub fn sign_policy(
    reference_values: oak_proto_rust::oak::attestation::v1::ReferenceValues,
    signing_key: SigningKey,
) -> Result<SignedAppraisalPolicy, String> {
    let policy_binary: Vec<u8> = encode_raw_policy(&reference_values)?;
    let signature: Signature = signing_key.sign(&policy_binary);
    Ok(SignedAppraisalPolicy {
        policy: Some(reference_values),
        signature: vec![SignatureWrapper {
            signature: signature.to_vec(),
            signer: "".to_string(),
        }],
    })
}

// TODO(b/358413924): Support signature id, multiple signatures
fn verify_policy_signature(
    signed_policy: &SignedAppraisalPolicy,
    verifying_keys: &Vec<VerifyingKey>,
    num_pass_required: usize,
) -> Result<oak_proto_rust::oak::attestation::v1::ReferenceValues, String> {
    if num_pass_required > 1 {
        return Err("Currently doesn't support checking multiple signatures".to_string());
    }
    let policy: oak_proto_rust::oak::attestation::v1::ReferenceValues =
        extract_raw_policy(signed_policy)?;
    if num_pass_required == 0 {
        return Ok(policy);
    } else {
        let signature: Signature = extract_signature(signed_policy)?;
        let policy_binary: Vec<u8> = encode_raw_policy(&policy)?;
        match verifying_keys[0].verify(policy_binary.as_slice(), &signature) {
            Ok(()) => Ok(policy),
            Err(e) => Err(format!("Failed to verify policy signature: {e}")),
        }
    }
}

// TODO(b/358413924): Support signature id, multiple signatures
fn extract_signature(signed_policy: &SignedAppraisalPolicy) -> Result<Signature, String> {
    if signed_policy.signature.is_empty() {
        return Err("No signature found.".to_string());
    }
    Signature::from_slice(signed_policy.signature[0].signature.as_slice())
        .map_err(|_| "Failed to parse signature.".to_string())
}

fn extract_raw_policy(
    signed_policy: &SignedAppraisalPolicy,
) -> Result<oak_proto_rust::oak::attestation::v1::ReferenceValues, String> {
    match signed_policy.policy.as_ref() {
        Some(x) => Ok(x.clone()),
        None => return Err("Failed to get policy as ref".to_string()),
    }
}

fn encode_raw_policy(
    policy: &oak_proto_rust::oak::attestation::v1::ReferenceValues,
) -> Result<Vec<u8>, String> {
    let mut policy_binary: Vec<u8> = Vec::with_capacity(1024);
    policy
        .encode(&mut policy_binary)
        .map_err(|e| format!("Failed to re-encode policy: {e}"))?;
    Ok(policy_binary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::privacy_sandbox::tvs::appraisal_policies::SignedAppraisalPolicy;
    use p256::ecdsa::{signature::Signer, signature::Verifier, SigningKey, VerifyingKey};
    use prost::Message;

    // Edit this to generate signatures for different policies
    // TODO: read this in as raw text (optional?), so that it's easier to manually enter a policy
    fn get_test_policy() -> SignedAppraisalPolicy {
        SignedAppraisalPolicy::decode(
            &include_bytes!("../test_data/on-perm-reference.binarypb")[..],
        )
        .unwrap()
    }

    fn get_test_signing_key() -> SigningKey {
        SigningKey::from_slice(
            &hex::decode("cf8d805ed629f4f95d20714a847773b3e53d3d8ab155e52c882646f702a98ce8")
                .unwrap(),
        )
        .unwrap()
    }

    fn get_test_verifying_key() -> VerifyingKey {
        VerifyingKey::from_sec1_bytes(
            &hex::decode("048fa2c25d3d3368b23f7877c9ac84866f440f9dd7a94e7ca5440ef1bc611f77db2940cca2233d06c9cfbf503ee73fdf5cf1f4c637f376bb7daaf637faf05656e4")
            .unwrap()
            )
        .unwrap()
    }

    // Escaped string for copying into textprotos for bytes fields
    fn to_escaped_string(s: &[u8]) -> String {
        String::from_utf8_lossy(
            s.iter()
                .flat_map(|b| std::ascii::escape_default(*b))
                .collect::<Vec<u8>>()
                .as_slice(),
        )
        .to_string()
    }

    #[test]
    fn test_testing_keys_match() {
        let signing_key: SigningKey = get_test_signing_key();
        let verifying_key = get_test_verifying_key();

        assert_eq!(verifying_key, VerifyingKey::from(&signing_key));
    }

    // This test also prints out expected signatures on failure.
    // Use this to manually sign policies for now.
    // TODO(b/358413924): have a separate tool/helper that can be used to sign policies instead. Currently having a main causes issues.
    #[test]
    fn test_extraction_correct() {
        let signed_policy: SignedAppraisalPolicy = get_test_policy();

        let signing_key: SigningKey = get_test_signing_key();
        let verifying_key: VerifyingKey = get_test_verifying_key();

        let raw_policy: oak_proto_rust::oak::attestation::v1::ReferenceValues =
            extract_raw_policy(&signed_policy).unwrap();
        let raw_policy_binary: Vec<u8> = encode_raw_policy(&raw_policy).unwrap();
        let expected_signature: Signature = signing_key.sign(&raw_policy_binary);

        match extract_signature(&signed_policy) {
            Ok(sig) => {
                assert!(
                    verifying_key
                        .verify(raw_policy_binary.as_slice(), &sig)
                        .is_ok(),
                    "Signature is incorrect.\nExpected signature: {}",
                    to_escaped_string(&expected_signature.to_bytes())
                );
            }
            Err(_e) => {
                println!(
                    "Failed to parse original signature.\nExpected signature: {}",
                    to_escaped_string(&expected_signature.to_bytes())
                );
            }
        }
    }

    #[test]
    fn test_decode_and_verify_correct() {
        let mut policies: Vec<u8> = Vec::with_capacity(1024);
        AppraisalPolicies {
            signed_policy: vec![get_test_policy()],
        }
        .encode(&mut policies)
        .unwrap();
        let verifying_keys = vec![get_test_verifying_key()];
        let decoded_policy = decode_and_verify_policies(&policies, verifying_keys, 1).unwrap();
        assert_eq!(decoded_policy.len(), 1);
        assert_eq!(get_test_policy().policy.unwrap(), decoded_policy[0]);
    }

    #[test]
    fn test_decode_and_verify_nocheck_correct() {
        let mut signed_policy: SignedAppraisalPolicy = get_test_policy();
        signed_policy.signature = vec![];
        let mut policies: Vec<u8> = Vec::with_capacity(1024);
        AppraisalPolicies {
            signed_policy: vec![signed_policy],
        }
        .encode(&mut policies)
        .unwrap();
        let decoded_policy = decode_and_verify_policies(&policies, vec![], 0).unwrap();
        assert_eq!(decoded_policy.len(), 1);
        assert_eq!(get_test_policy().policy.unwrap(), decoded_policy[0]);
    }

    #[test]
    fn test_extract_signature_parse_error() {
        let mut policy: SignedAppraisalPolicy = get_test_policy();
        policy.signature[0].signature = b"asfd".to_vec();

        match extract_signature(&policy) {
            Ok(_) => assert!(false, "Should fail to parse signature."),
            Err(e) => assert_eq!(e, "Failed to parse signature.".to_string()),
        }
    }

    #[test]
    fn test_extract_signature_none_error() {
        let mut policy: SignedAppraisalPolicy = get_test_policy();
        policy.signature = vec![];

        match extract_signature(&policy) {
            Ok(_) => assert!(false, "Should complain about no signatures."),
            Err(e) => assert_eq!(e, "No signature found.".to_string()),
        }
    }

    #[test]
    fn test_decode_and_verify_bad_decode() {
        let policies = b"foo";
        let verifying_keys = vec![get_test_verifying_key()];
        match decode_and_verify_policies(policies, verifying_keys, 1) {
            Ok(_) => assert!(false, "Should fail to decode policies."),
            Err(e) => assert_eq!(
                e,
                "Failed to decode (serialize) appraisal policy.".to_string()
            ),
        }
    }

    #[test]
    fn test_verify_signature_incorrect() {
        let mut policy: SignedAppraisalPolicy = get_test_policy();
        let sig_length = policy.signature[0].signature.len();
        policy.signature[0].signature = vec![b'0'; sig_length];

        let verifying_keys = vec![get_test_verifying_key()];
        match verify_policy_signature(&policy, &verifying_keys, 1) {
            Ok(_) => assert!(false, "Should fail to with incorrect signature."),
            Err(e) => assert_eq!(
                e,
                "Failed to verify policy signature: signature error".to_string()
            ),
        }
    }

    #[test]
    fn test_sign_policy() {
        let signed_policy: SignedAppraisalPolicy = get_test_policy();
        let signing_key: SigningKey = get_test_signing_key();

        let raw_policy: oak_proto_rust::oak::attestation::v1::ReferenceValues =
            extract_raw_policy(&signed_policy).unwrap();
        let new_signed_policy: SignedAppraisalPolicy =
            sign_policy(raw_policy, signing_key).unwrap();
        assert_eq!(signed_policy, new_signed_policy);
    }
}
