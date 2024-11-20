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
#![no_main]
#![feature(alloc_error_handler)]
extern crate alloc;
use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use enclave_service::EnclaveService;
use oak_proto_rust::oak::attestation::v1::TcbVersion;
use oak_restricted_kernel_sdk::{
    channel::{start_blocking_server, FileDescriptorChannel},
    entrypoint,
    utils::samplestore::StaticSampleStore,
};
use prost::Message;
use tvs_enclave::proto::privacy_sandbox::tvs::TvsEnclaveServer;
use tvs_proto::privacy_sandbox::tvs::{
    stage0_measurement, AmdSev, AppraisalPolicies, AppraisalPolicy, Measurement,
    Signature as PolicySignature, Stage0Measurement,
};

#[entrypoint]
fn start_server() -> ! {
    let key_service = Box::new(KeyFetcherService {});
    let trusted_tvs = trusted_tvs::service::Service::new(
        key_service,
        get_appraisal_policies().as_slice(),
        /*enable_policy_signature=*/ true,
        /*accept_insecure_policies=*/ false,
    )
    .expect("failed to create TrustedTvs service");

    let enclave_service = EnclaveService::new(&trusted_tvs);
    let server = TvsEnclaveServer::new(enclave_service);
    let mut invocation_stats =
        StaticSampleStore::<1000>::new().expect("failed to create StaticSampleStore");

    log::info!("Starting TVS...");
    start_blocking_server(
        Box::<FileDescriptorChannel>::default(),
        server,
        &mut invocation_stats,
    )
    .expect("server encountered an unrecoverable error");
}

// TODO(alwabel): update the key fetcher so that keys are not hard coded.
pub struct KeyFetcherService {}
impl key_provider::KeyProvider for KeyFetcherService {
    fn get_primary_private_key(&self) -> anyhow::Result<Vec<u8>> {
        let mut a: [u8; 32] = [0; 32];
        a[31] = 1;
        Ok(a.to_vec())
    }

    fn get_secondary_private_key(&self) -> Option<anyhow::Result<Vec<u8>>> {
        None
    }

    fn user_id_for_authentication_key(&self, _public_key: &[u8]) -> anyhow::Result<i64> {
        Ok(1)
    }

    fn get_secrets_for_user_id(&self, _user_id: i64) -> anyhow::Result<Vec<u8>> {
        Ok(b"secret".to_vec())
    }
}

fn get_appraisal_policies() -> Vec<u8> {
    let policies = AppraisalPolicies {
            policies: vec![AppraisalPolicy{
                measurement: Some(Measurement {
                    stage0_measurement: Some(Stage0Measurement{
                        r#type: Some(stage0_measurement::Type::AmdSev(AmdSev{
                            sha384: "4cca87bd71495f8484343f9524bf9a866c98851b8bfcadbd385fdc798ace74fce976ebe70c3d6ded70b86980cab5e4c5".to_string(),
                            min_tcb_version: Some(TcbVersion{
                                boot_loader: 7,
                                microcode: 62,
                                snp: 15,
                                tee: 0,
                            }),
                        })),
                    }),
                    kernel_image_sha256: "eca5ef41f6dc7e930d8e9376e78d19802c49f5a24a14c0be18c8e0e3a8be3e84".to_string(),
                    kernel_setup_data_sha256: "9745b0f42d03054bb49033b766177e571f51f511c1368611d2ee268a704c641b".to_string(),
                    init_ram_fs_sha256: "7cd4896bdd958f67a6a85cc1cc780761ac9615bc25ae4436aad1d4e9d2332c1a".to_string(),
                    memory_map_sha256: "c9a26ba0a492465327894303dc6b1bd23a41cc1093fe96daa05fa7de0d25e392".to_string(),
                    acpi_table_sha256: "6006fa52084ec0da69ff2e63bb4abba78a4aeeb457f4eb4d3a75b3b114ec862d".to_string(),
                    kernel_cmd_line_regex: "^ console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=10485760 brd.max_part=1 ip=10.0.2.15:::255.255.255.0::enp0s1:off quiet -- --launcher-addr=vsock://2:.*$".to_string(),
                    system_image_sha256: "49a3b093050502412e0c7dd2f58a9f2197ca0c48c3a46fad048da80a04bfc601".to_string(),
                    container_binary_sha256:"cb31d889e33eaf9e3b43cdbeb3554903c36b5e037c5187e876a69e8c5b5d864c".to_string(),

                }),
                signature: vec![PolicySignature{
                    signature: "3ff1710e37f34d96f11025d747f67a865998a98caa7e2ba4cb3924cba445e216533919567816e677473f9efd528ae0fc61588fc337a4b95748d93052c58f8a28".to_string(),
                    signer: "".to_string(),
                    },
                    ],
            }],
    };
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    policies.encode(&mut buf).unwrap();
    buf
}
