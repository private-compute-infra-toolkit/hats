// Copyright 2025 Google LLC.
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

//! This crate provides shared utilities for testing TVS components that
//! require dynamic attestation policies and artifacts.

use oak_proto_rust::oak::attestation::v1::TcbVersion;
use prost::Message;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use tvs_proto::pcit::tvs::{
    stage0_measurement, AmdSevDynamic, AppraisalPolicies, AppraisalPolicy, CpuInfo, Measurement,
    Signature as PolicySignature, Stage0Measurement,
};

// Statically include the stage0 binary contents at compile time.
const STAGE0_BINARY: &[u8] = include_bytes!("../../test_data/stage0_bin_for_test");

/// Creates a serialized dynamic appraisal policy for Genoa with a single container.
pub fn create_dynamic_genoa_policy() -> Vec<u8> {
    let stage0_blob = STAGE0_BINARY.to_vec();
    let stage0_hash = hex::encode(Sha256::digest(&stage0_blob));

    let policies = AppraisalPolicies {
        policies: vec![AppraisalPolicy {
            description: "Test against golden dynamic evidence genoa".to_string(),
            measurement: Some(Measurement {
                stage0_measurement: Some(Stage0Measurement {
                    r#type: Some(stage0_measurement::Type::AmdSevDynamic(AmdSevDynamic {
                        stage0_ovmf_binary_hash: vec![stage0_hash.clone()],
                        min_tcb_version: Some(TcbVersion {
                            boot_loader: 10,
                            microcode: 84,
                            snp: 25,
                            ..Default::default()
                        }),
                        cpu_info: vec![CpuInfo { family: 25, model: 17, stepping: 1 }],
                        vcpu_count: vec![4],
                    })),
                }),
                kernel_image_sha256: "f9d0584247b46cc234a862aa8cd08765b38405022253a78b9af189c4cedbe447".to_string(),
                kernel_setup_data_sha256: "75f091da89ce81e9decb378c3b72a948aed5892612256b3a6e8305ed034ec39a".to_string(),
                init_ram_fs_sha256: "b2b5eda097c2e15988fd3837145432e3792124dbe0586edd961efda497274391".to_string(),
                memory_map_sha256: "11103720aab9f4eff4b68b7573b6968e3947e5d7552ace7cebacdbdb448b68fe".to_string(),
                acpi_table_sha256: "194afdde1699c335fdd4ed99fd36d9500230fbda0ab14f6d95fc35d219ddf32e".to_string(),
                kernel_cmd_line_regex: "^ console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=10485760 brd.max_part=1 ip=10.0.2.15:::255.255.255.0::enp0s1:off quiet -- --launcher-addr=vsock://2:.*$".to_string(),
                system_image_sha256: "3c59bd10c2b890ff152cc57fdca0633693acbb04982da90c670de6530fa8a836".to_string(),
                container_binary_sha256: vec!["b0803886a6e096bf1c9eacaa77dd1514134d2e88a7734af9ba2dbf650884f899".to_string()],
            }),
            signature: vec![PolicySignature {
                signature: "972449509fe27fa8fffbebe77b83ed908e698b6efa09727c38fbd84186db79b24a79f5a40ddbda77b3db066293c4931f8b036d0f2193326f2b7b8dd3de80509f".to_string(),
                signer: "".to_string(),
            }],
        }],
        stage0_binary_sha256_to_blob: BTreeMap::from([(stage0_hash, stage0_blob)]),
    };
    let mut buf = Vec::new();
    policies.encode(&mut buf).unwrap();
    buf
}

/// Creates a serialized dynamic appraisal policy for Genoa with multiple containers.
pub fn create_dynamic_genoa_policy_multiple_containers() -> Vec<u8> {
    let stage0_blob = STAGE0_BINARY.to_vec();
    let stage0_hash = hex::encode(Sha256::digest(&stage0_blob));

    let policies = AppraisalPolicies {
        policies: vec![AppraisalPolicy {
            description: "Test against golden dynamic evidence genoa".to_string(),
            measurement: Some(Measurement {
                stage0_measurement: Some(Stage0Measurement {
                    r#type: Some(stage0_measurement::Type::AmdSevDynamic(AmdSevDynamic {
                        stage0_ovmf_binary_hash: vec![stage0_hash.clone()],
                        min_tcb_version: Some(TcbVersion {
                            boot_loader: 10,
                            microcode: 84,
                            snp: 25,
                            ..Default::default()
                        }),
                        cpu_info: vec![CpuInfo { family: 25, model: 17, stepping: 1 }],
                        vcpu_count: vec![4],
                    })),
                }),
                kernel_image_sha256: "f9d0584247b46cc234a862aa8cd08765b38405022253a78b9af189c4cedbe447".to_string(),
                kernel_setup_data_sha256: "75f091da89ce81e9decb378c3b72a948aed5892612256b3a6e8305ed034ec39a".to_string(),
                init_ram_fs_sha256: "b2b5eda097c2e15988fd3837145432e3792124dbe0586edd961efda497274391".to_string(),
                memory_map_sha256: "11103720aab9f4eff4b68b7573b6968e3947e5d7552ace7cebacdbdb448b68fe".to_string(),
                acpi_table_sha256: "194afdde1699c335fdd4ed99fd36d9500230fbda0ab14f6d95fc35d219ddf32e".to_string(),
                kernel_cmd_line_regex: "^ console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=10485760 brd.max_part=1 ip=10.0.2.15:::255.255.255.0::enp0s1:off quiet -- --launcher-addr=vsock://2:.*$".to_string(),
                system_image_sha256: "3c59bd10c2b890ff152cc57fdca0633693acbb04982da90c670de6530fa8a836".to_string(),
                container_binary_sha256: vec![
                    "b0803886a6e096bf1c9eacaa77dd1514134d2e88a7734af9ba2dbf650884f899".to_string(),
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
                ],
            }),
            signature: vec![PolicySignature {
                signature: "41e353c8379bb730108a50bf32b95d2f196dc2fa1fc7434abb564292814dd534f99610e2685f612295d1e085543cef9fde2fef2327dc6cb0aba3236ae8cc2971".to_string(),
                signer: "".to_string(),
            }],
        }],
        stage0_binary_sha256_to_blob: BTreeMap::from([(stage0_hash, stage0_blob)]),
    };
    let mut buf = Vec::new();
    policies.encode(&mut buf).unwrap();
    buf
}
