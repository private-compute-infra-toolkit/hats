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
#![no_std]

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use p256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
use tvs_proto::privacy_sandbox::tvs::AppraisalPolicy;

/// Validate and generate signatures attached to an appraisal policy.
///
/// Sign an appraisal policy using the provided key. The measurements are
/// converted from hex strings to bytes, concatenated and signed.
// TODO(b/358413924): Support signature id, multiple signatures
pub fn sign_policy(policy: &AppraisalPolicy, signing_key: &SigningKey) -> anyhow::Result<Vec<u8>> {
    let signature: Signature = signing_key.sign(&policy_to_bytes(policy)?);
    Ok(signature.to_vec())
}

/// Verify the signature on the given policy using the given verifying_keys.
/// num_pass_required signifies the minimum number of valid signature on
/// the policy.
// TODO(b/358413924): Support signature id, multiple signatures
pub fn verify_policy_signature(
    policy: &AppraisalPolicy,
    verifying_keys: &[&VerifyingKey],
    num_pass_required: u32,
) -> anyhow::Result<()> {
    if num_pass_required > 1 {
        anyhow::bail!("Currently doesn't support checking multiple signatures.");
    }
    if num_pass_required == 0 {
        anyhow::bail!("num_pass_required should be greater than zero.");
    }
    if num_pass_required != 0 {
        let signature: Signature = extract_signature(policy)?;
        let policy_binary = policy_to_bytes(policy)?;
        verifying_keys[0]
            .verify(policy_binary.as_slice(), &signature)
            .map_err(|err| anyhow::anyhow!("Failed to verify policy signature: {err}"))?;
    }
    Ok(())
}

// TODO(b/358413924): Support signature id, multiple signatures
fn policy_to_bytes(policy: &AppraisalPolicy) -> anyhow::Result<Vec<u8>> {
    let Some(measurement) = &policy.measurement else {
        anyhow::bail!("Policy does not have measurement field set.");
    };
    let Some(stage0_measurement) = &measurement.stage0_measurement else {
        anyhow::bail!("stage0_measurement field is not set");
    };

    let mut binary_data = vec![];
    if let Some(tvs_proto::privacy_sandbox::tvs::stage0_measurement::Type::AmdSev(stage0)) =
        stage0_measurement.r#type.as_ref()
    {
        let Some(min_tcb_version) = &stage0.min_tcb_version else {
            anyhow::bail!("min_tcb_version is not set");
        };
        binary_data.extend(
            hex::decode(&stage0.sha384)
                .map_err(|err| anyhow::anyhow!("Failed to decode stage0 sha384: {err}"))?,
        );
        binary_data.extend(min_tcb_version.boot_loader.to_be_bytes());
        binary_data.extend(min_tcb_version.tee.to_be_bytes());
        binary_data.extend(min_tcb_version.snp.to_be_bytes());
        binary_data.extend(min_tcb_version.microcode.to_be_bytes());
    }

    binary_data.extend(
        hex::decode(&measurement.kernel_image_sha256)
            .map_err(|err| anyhow::anyhow!("Failed to decode kernel_image_sha256: {err}"))?,
    );
    binary_data.extend(
        hex::decode(&measurement.kernel_setup_data_sha256)
            .map_err(|err| anyhow::anyhow!("Failed to decode kernel_setup_data_sha256: {err}"))?,
    );
    binary_data.extend(
        hex::decode(&measurement.init_ram_fs_sha256)
            .map_err(|err| anyhow::anyhow!("Failed to decode init_ram_fs_sha256: {err}"))?,
    );
    binary_data.extend(
        hex::decode(&measurement.memory_map_sha256)
            .map_err(|err| anyhow::anyhow!("Failed to decode memory_map_sha256: {err}"))?,
    );
    binary_data.extend(
        hex::decode(&measurement.acpi_table_sha256)
            .map_err(|err| anyhow::anyhow!("Failed to decode acpi_table_sha256: {err}"))?,
    );
    binary_data.extend(measurement.kernel_cmd_line_regex.bytes());
    binary_data.extend(
        hex::decode(&measurement.system_image_sha256)
            .map_err(|err| anyhow::anyhow!("Failed to decode system_image_sha256: {err}"))?,
    );

    for hex_string in &measurement.container_binary_sha256 {
        binary_data.extend(
            hex::decode(hex_string).map_err(|err| {
                anyhow::anyhow!("Failed to decode container_binary_sha256: {err}")
            })?,
        );
    }

    Ok(binary_data)
}

// TODO(b/358413924): Support signature id, multiple signatures
fn extract_signature(policy: &AppraisalPolicy) -> anyhow::Result<Signature> {
    if policy.signature.is_empty() {
        anyhow::bail!("No signature found.");
    }
    Signature::from_slice(
        &hex::decode(&policy.signature[0].signature)
            .map_err(|err| anyhow::anyhow!("Failed to decode signature: {err}"))?,
    )
    .map_err(|err| anyhow::anyhow!("Failed to parse signature: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alloc::string::{String, ToString};
    use oak_proto_rust::oak::attestation::v1::TcbVersion;
    use tvs_proto::privacy_sandbox::tvs::{
        stage0_measurement, AmdSev, Measurement, Signature as SignatureWrapper, Stage0Measurement,
    };

    fn get_test_policy() -> AppraisalPolicy {
        AppraisalPolicy{
                description: "Test AMD-SNP measurements".to_string(),
                measurement: Some(Measurement {
                    stage0_measurement: Some(Stage0Measurement{
                        r#type: Some(stage0_measurement::Type::AmdSev(AmdSev{
                            sha384: String::from("de654ed1eb03b69567338d357f86735c64fc771676bcd5d05ca6afe86f3eb9f7549222afae6139a8d282a34d09d59f95"),
                            min_tcb_version: Some(TcbVersion{
                                boot_loader: 7,
                                microcode: 62,
                                snp: 15,
                                tee: 0,
                                fmc: 0,
                            }),
                        })),
                    }),
                    kernel_image_sha256: String::from("442a36913e2e299da2b516814483b6acef11b63e03f735610341a8561233f7bf"),
                    kernel_setup_data_sha256: String::from("68cb426afaa29465f7c71f26d4f9ab5a82c2e1926236648bec226a8194431db9"),
                    init_ram_fs_sha256: String::from("3b30793d7f3888742ad63f13ebe6a003bc9b7634992c6478a6101f9ef323b5ae"),
                    memory_map_sha256: String::from("4c985428fdc6101c71cc26ddc313cd8221bcbc54471991ec39b1be026d0e1c28"),
                    acpi_table_sha256: String::from("a4df9d8a64dcb9a713cec028d70d2b1599faef07ccd0d0e1816931496b4898c8"),
                    kernel_cmd_line_regex: String::from("^ console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=10000000 brd.max_part=1 ip=10.0.2.15:::255.255.255.0::eth0:off$"),
                    system_image_sha256: String::from("e3ded9e7cfd953b4ee6373fb8b412a76be102a6edd4e05aa7f8970e20bfc4bcd"),
                    container_binary_sha256: vec![String::from("bf173d846c64e5caf491de9b5ea2dfac349cfe22a5e6f03ad8048bb80ade430c")],
                }),
                signature: vec![SignatureWrapper{
                    signature: String::from("003cfc8524266b283d4381e967680765bbd2a9ac2598eb256ba82ba98b3e23b384e72ad846c4ec3ff7b0791a53011b51d5ec1f61f61195ff083c4a97d383c13c"),
                    signer: String::from(""),
                    }],
            }
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

    #[test]
    fn test_verify_signature_success() {
        assert!(
            verify_policy_signature(&get_test_policy(), &[&get_test_verifying_key()], 1).is_ok()
        );
    }

    #[test]
    fn test_verify_signature_error() {
        let mut policy: AppraisalPolicy = get_test_policy();
        policy.measurement.as_mut().unwrap().kernel_image_sha256 =
            String::from("zzzzz6913e2e299da2b516814483b6acef11b63e03f735610341a8561233f7ba");
        match verify_policy_signature(&policy, &[&get_test_verifying_key()], 1) {
            Ok(_) => panic!("Should fail to with malformed signature."),
            Err(e) => {
                assert_eq!(
                    e.to_string(),
                    "Failed to decode kernel_image_sha256: Invalid character 'z' at position 0"
                )
            }
        }

        let mut policy: AppraisalPolicy = get_test_policy();
        let sig_length = policy.signature[0].signature.len();
        policy.signature[0].signature = "0".repeat(sig_length);
        match verify_policy_signature(&policy, &[&get_test_verifying_key()], 1) {
            Ok(_) => panic!("Should fail to with malformed signature."),
            Err(e) => assert_eq!(
                e.to_string(),
                "Failed to parse signature: signature error".to_string()
            ),
        }

        let mut policy: AppraisalPolicy = get_test_policy();
        policy.measurement.as_mut().unwrap().kernel_image_sha256 =
            "442a36913e2e299da2b516814483b6acef11b63e03f735610341a8561233f7ba".to_string();
        match verify_policy_signature(&policy, &[&get_test_verifying_key()], 1) {
            Ok(_) => panic!("Should fail to with incorrect signature."),
            Err(e) => assert_eq!(
                e.to_string(),
                "Failed to verify policy signature: signature error".to_string()
            ),
        }

        let mut policy: AppraisalPolicy = get_test_policy();
        policy.signature = vec![];
        match verify_policy_signature(&policy, &[&get_test_verifying_key()], 1) {
            Ok(_) => panic!("Should fail with no signature."),
            Err(e) => assert_eq!(e.to_string(), "No signature found.".to_string(),),
        }

        match verify_policy_signature(&get_test_policy(), &[&get_test_verifying_key()], 0) {
            Ok(_) => panic!("Should fail to with zero signature threshold."),
            Err(e) => assert_eq!(
                e.to_string(),
                "num_pass_required should be greater than zero.".to_string(),
            ),
        }
    }

    #[test]
    fn test_sign_policy() {
        let mut policy: AppraisalPolicy = get_test_policy();
        policy.signature = vec![];
        let signing_key: SigningKey = get_test_signing_key();
        assert_eq!(hex::encode(sign_policy(&policy, &signing_key).unwrap()), "003cfc8524266b283d4381e967680765bbd2a9ac2598eb256ba82ba98b3e23b384e72ad846c4ec3ff7b0791a53011b51d5ec1f61f61195ff083c4a97d383c13c");
    }
}
