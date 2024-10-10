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
use oak_proto_rust::oak::attestation::v1::{
    binary_reference_value, endorsements, kernel_binary_reference_value, reference_values,
    text_reference_value, AmdSevReferenceValues, BinaryReferenceValue,
    ContainerLayerReferenceValues, Digests, Endorsements, Evidence, InsecureReferenceValues,
    KernelBinaryReferenceValue, KernelDigests, KernelLayerReferenceValues,
    OakContainersEndorsements, OakContainersReferenceValues, ReferenceValues, Regex,
    RootLayerEndorsements, RootLayerReferenceValues, SkipVerification, SystemLayerReferenceValues,
    TextReferenceValue,
};
use oak_proto_rust::oak::RawDigest;
use p256::ecdsa::VerifyingKey;
use prost::Message;
use tvs_proto::privacy_sandbox::tvs::{
    stage0_measurement, AppraisalPolicies, AppraisalPolicy, Measurement,
};

pub struct PolicyManager {
    reference_values: Vec<ReferenceValues>,
}

impl PolicyManager {
    pub fn new(
        policies: &[u8],
        enable_policy_signature: bool,
        accept_insecure_policies: bool,
    ) -> anyhow::Result<Self> {
        let appraisal_policies = AppraisalPolicies::decode(policies)
            .map_err(|_| anyhow::anyhow!("Failed to decode (serialize) appraisal policy."))?;
        let reference_values = if enable_policy_signature {
            let policy_verifying_key: VerifyingKey = get_policy_public_key()?;
            process_and_validate_policies(
                appraisal_policies,
                &[&policy_verifying_key],
                /*num_pass_required=*/ 1,
                accept_insecure_policies,
            )
        } else {
            process_and_validate_policies(
                appraisal_policies,
                &[],
                /*num_pass_required=*/ 0,
                accept_insecure_policies,
            )
        }?;
        Ok(Self { reference_values })
    }
    // Check evidence against the appraisal policies.
    pub fn check_evidence(
        &self,
        time_milis: i64,
        evidence: &Evidence,
        tee_certificate: &[u8],
    ) -> anyhow::Result<()> {
        let endorsement = create_endorsements(tee_certificate);
        for policy in &self.reference_values {
            match oak_attestation_verification::verifier::verify(
                time_milis,
                evidence,
                &endorsement,
                policy,
            ) {
                Ok(_) => return Ok(()),
                Err(_) => continue,
            };
        }
        Err(anyhow::anyhow!(
            "Failed to verify report. No matching appraisal policy found"
        ))
    }
}

// TODO(b/358413924): Actually fetch key
fn get_policy_public_key() -> anyhow::Result<VerifyingKey> {
    let verifying_key = VerifyingKey::from_sec1_bytes(
        &hex::decode("048fa2c25d3d3368b23f7877c9ac84866f440f9dd7a94e7ca5440ef1bc611f77db2940cca2233d06c9cfbf503ee73fdf5cf1f4c637f376bb7daaf637faf05656e4")
        .map_err(|err| anyhow::anyhow!("Failed to decode policy public key hex: {err}"))?
    )
    .map_err(|err| anyhow::anyhow!("Failed to parse policy public key: {err}"))?;
    Ok(verifying_key)
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

fn process_and_validate_policies(
    policies: AppraisalPolicies,
    verifying_keys: &[&VerifyingKey],
    num_pass_required: u32,
    accept_insecure_policies: bool,
) -> anyhow::Result<Vec<ReferenceValues>> {
    policies
        .policies
        .into_iter()
        .map(|policy| {
            if num_pass_required == 0 {
                Ok(policy)
            } else {
                match policy_signature::verify_policy_signature(
                    &policy,
                    verifying_keys,
                    num_pass_required,
                ) {
                    Ok(_) => Ok(policy),
                    Err(e) => Err(e),
                }
            }
        })
        .map(|policy| appraisal_policy_to_reference_values(&policy?, accept_insecure_policies))
        .collect()
}

fn appraisal_policy_to_reference_values(
    policy: &AppraisalPolicy,
    accept_insecure_policies: bool,
) -> anyhow::Result<ReferenceValues> {
    let Some(measurement) = &policy.measurement else {
        anyhow::bail!("Policy does not have measurement field set");
    };

    Ok(ReferenceValues {
        r#type: Some(reference_values::Type::OakContainers(
            OakContainersReferenceValues {
                root_layer: Some(get_root_layer(measurement, accept_insecure_policies)?),
                kernel_layer: Some(get_kernel_layer(measurement)?),
                system_layer: Some(get_system_layer(measurement)?),
                container_layer: Some(get_container_layer(measurement)?),
            },
        )),
    })
}

fn get_root_layer(
    measurement: &Measurement,
    accept_insecure_policies: bool,
) -> anyhow::Result<RootLayerReferenceValues> {
    let Some(stage0_measurement) = &measurement.stage0_measurement else {
        anyhow::bail!("stage0_measurement field is not set");
    };
    match stage0_measurement.r#type.as_ref() {
        Some(stage0_measurement::Type::AmdSev(stage0)) => {
            if stage0.min_tcb_version.is_none() {
                anyhow::bail!("min_tcb_version is not set");
            }
            Ok(RootLayerReferenceValues {
                amd_sev: Some(AmdSevReferenceValues {
                    allow_debug: false,
                    min_tcb_version: stage0.min_tcb_version.clone(),
                    stage0: Some(BinaryReferenceValue {
                        r#type: Some(binary_reference_value::Type::Digests(Digests {
                            digests: vec![RawDigest {
                                sha2_384: hex::decode(&stage0.sha384).map_err(|err| {
                                    anyhow::anyhow!("failed to decode sha256_hex: {err}")
                                })?,
                                psha2: vec![],
                                sha1: vec![],
                                sha2_256: vec![],
                                sha2_512: vec![],
                                sha3_512: vec![],
                                sha3_384: vec![],
                                sha3_256: vec![],
                                sha3_224: vec![],
                            }],
                        })),
                    }),
                }),
                insecure: None,
                intel_tdx: None,
            })
        }
        Some(stage0_measurement::Type::Insecure(_)) => {
            if !accept_insecure_policies {
                anyhow::bail!("Cannot accept insecure policies.");
            }
            Ok(RootLayerReferenceValues {
                insecure: Some(InsecureReferenceValues {}),
                amd_sev: None,
                intel_tdx: None,
            })
        }
        None => Err(anyhow::anyhow!("stage0_measurement field is not set")),
    }
}

fn get_kernel_layer(measurement: &Measurement) -> anyhow::Result<KernelLayerReferenceValues> {
    // A number of deprecated field that we have to set, and when we do we get warned.
    // So we suppress the warning.
    #[allow(deprecated)]
    Ok(KernelLayerReferenceValues {
        kernel: Some(KernelBinaryReferenceValue {
            r#type: Some(kernel_binary_reference_value::Type::Digests(
                KernelDigests {
                    image: Some(sha256_hex_to_digest(&measurement.kernel_image_sha256)?),
                    setup_data: Some(sha256_hex_to_digest(&measurement.kernel_setup_data_sha256)?),
                },
            )),
        }),
        kernel_cmd_line_text: Some(TextReferenceValue {
            r#type: Some(text_reference_value::Type::Regex(Regex {
                value: measurement.kernel_cmd_line_regex.clone(),
            })),
        }),
        init_ram_fs: Some(BinaryReferenceValue {
            r#type: Some(binary_reference_value::Type::Digests(sha256_hex_to_digest(
                &measurement.init_ram_fs_sha256,
            )?)),
        }),
        memory_map: Some(BinaryReferenceValue {
            r#type: Some(binary_reference_value::Type::Digests(sha256_hex_to_digest(
                &measurement.memory_map_sha256,
            )?)),
        }),
        acpi: Some(BinaryReferenceValue {
            r#type: Some(binary_reference_value::Type::Digests(sha256_hex_to_digest(
                &measurement.acpi_table_sha256,
            )?)),
        }),
        // Deprecated fields that are not used anymore.
        kernel_setup_data: None,
        kernel_image: None,
        kernel_cmd_line_regex: None,
        kernel_cmd_line: None,
    })
}

fn get_system_layer(measurement: &Measurement) -> anyhow::Result<SystemLayerReferenceValues> {
    Ok(SystemLayerReferenceValues {
        system_image: Some(BinaryReferenceValue {
            r#type: Some(binary_reference_value::Type::Digests(sha256_hex_to_digest(
                &measurement.system_image_sha256,
            )?)),
        }),
    })
}

fn get_container_layer(measurement: &Measurement) -> anyhow::Result<ContainerLayerReferenceValues> {
    Ok(ContainerLayerReferenceValues {
        binary: Some(BinaryReferenceValue {
            r#type: Some(binary_reference_value::Type::Digests(sha256_hex_to_digest(
                &measurement.container_binary_sha256,
            )?)),
        }),
        // Skip configuration verification as we are not using it.
        configuration: Some(BinaryReferenceValue {
            r#type: Some(binary_reference_value::Type::Skip(SkipVerification {})),
        }),
    })
}

fn sha256_hex_to_digest(sha256_hex: &str) -> anyhow::Result<Digests> {
    Ok(Digests {
        digests: vec![RawDigest {
            sha2_256: hex::decode(sha256_hex)
                .map_err(|err| anyhow::anyhow!("failed to decode sha256_hex: {err}"))?,
            psha2: vec![],
            sha1: vec![],
            sha2_512: vec![],
            sha3_512: vec![],
            sha3_384: vec![],
            sha3_256: vec![],
            sha3_224: vec![],
            sha2_384: vec![],
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alloc::string::ToString;
    use alloc::string::String;
    use oak_proto_rust::oak::attestation::v1::TcbVersion;
    use prost::Message;
    use tvs_proto::privacy_sandbox::tvs::{
        stage0_measurement, AmdSev, Signature, Stage0Measurement,
    };

    fn default_appraisal_policies() -> Vec<u8> {
        let policies = AppraisalPolicies {
            policies: vec![AppraisalPolicy{
                measurement: Some(Measurement {
                    stage0_measurement: Some(Stage0Measurement{
                        r#type: Some(stage0_measurement::Type::AmdSev(AmdSev{
                            sha384: String::from("de654ed1eb03b69567338d357f86735c64fc771676bcd5d05ca6afe86f3eb9f7549222afae6139a8d282a34d09d59f95"),
                            min_tcb_version: Some(TcbVersion{
                                boot_loader: 7,
                                microcode: 62,
                                snp: 15,
                                tee: 0,
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
                    container_binary_sha256:String::from("bf173d846c64e5caf491de9b5ea2dfac349cfe22a5e6f03ad8048bb80ade430c"),

                }),
                signature: vec![Signature{
                    signature: String::from("003cfc8524266b283d4381e967680765bbd2a9ac2598eb256ba82ba98b3e23b384e72ad846c4ec3ff7b0791a53011b51d5ec1f61f61195ff083c4a97d383c13c"),
                    signer: String::from(""),
                    },
                    ],
            }],
        };
        let mut buf: Vec<u8> = Vec::with_capacity(1024);
        policies.encode(&mut buf).unwrap();
        buf
    }

    fn insecure_appraisal_policies() -> Vec<u8> {
        let policies = AppraisalPolicies {
            policies: vec![AppraisalPolicy{
                measurement: Some(Measurement {
                    stage0_measurement: Some(Stage0Measurement{
                        r#type: Some(stage0_measurement::Type::Insecure(InsecureReferenceValues{})),
                    }),
                    kernel_image_sha256: String::from("442a36913e2e299da2b516814483b6acef11b63e03f735610341a8561233f7bf"),
                    kernel_setup_data_sha256: String::from("68cb426afaa29465f7c71f26d4f9ab5a82c2e1926236648bec226a8194431db9"),
                    init_ram_fs_sha256: String::from("3b30793d7f3888742ad63f13ebe6a003bc9b7634992c6478a6101f9ef323b5ae"),
                    memory_map_sha256: String::from("4c985428fdc6101c71cc26ddc313cd8221bcbc54471991ec39b1be026d0e1c28"),
                    acpi_table_sha256: String::from("a4df9d8a64dcb9a713cec028d70d2b1599faef07ccd0d0e1816931496b4898c8"),
                    kernel_cmd_line_regex: String::from("^ console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=10000000 brd.max_part=1 ip=10.0.2.15:::255.255.255.0::eth0:off$"),
                    system_image_sha256: String::from("e3ded9e7cfd953b4ee6373fb8b412a76be102a6edd4e05aa7f8970e20bfc4bcd"),
                    container_binary_sha256:String::from("bf173d846c64e5caf491de9b5ea2dfac349cfe22a5e6f03ad8048bb80ade430c"),

                }),
                signature: vec![Signature{
                    signature: String::from("6870ebf5f55debe04cd66d47ea3b2a878edd436aba59be30b1f52478bb4e12e4d40c223664ee3c0f13ce27e159bc8e7726cce52520f4fb171d6622a26169dcb6"),
                    signer: String::from(""),
                    },
                    ],
            }],
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
            &default_appraisal_policies(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        )
        .unwrap();
        assert!(policy_manager
            .check_evidence(NOW_UTC_MILLIS, &get_good_evidence(), &get_genoa_vcek())
            .is_ok());
    }

    #[test]
    fn check_evidence_error() {
        let policy_manager = PolicyManager::new(
            &default_appraisal_policies(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        )
        .unwrap();
        match policy_manager.check_evidence(NOW_UTC_MILLIS, &get_bad_evidence(), &get_genoa_vcek())
        {
            Ok(_) => panic!("check_evidence() should fail."),
            Err(e) => assert_eq!(
                e.to_string(),
                "Failed to verify report. No matching appraisal policy found"
            ),
        }
    }

    #[test]
    fn policy_manager_creation_error() {
        match PolicyManager::new(
            /*policies=*/ &[1, 2, 3],
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        ) {
            Ok(_) => panic!("PolicyManager::new() should fail."),
            Err(e) => assert_eq!(
                e.to_string(),
                "Failed to decode (serialize) appraisal policy."
            ),
        }

        match PolicyManager::new(
            &insecure_appraisal_policies(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        ) {
            Ok(_) => panic!("PolicyManager::new() should fail."),
            Err(e) => assert_eq!(e.to_string(), "Cannot accept insecure policies."),
        }
    }
}
