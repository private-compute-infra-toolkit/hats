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

use crate::request_handler::RequestHandler;
use crypto::{P256Scalar, P256_SCALAR_LENGTH, P256_X962_LENGTH};
use policy_manager::PolicyManager;

pub struct Service {
    primary_private_key: P256Scalar,
    primary_public_key: [u8; P256_X962_LENGTH],
    secondary_private_key: Option<P256Scalar>,
    secondary_public_key: Option<[u8; P256_X962_LENGTH]>,
    policy_manager: PolicyManager,
}

pub fn new_service(
    primary_private_key: &[u8],
    policies: &[u8],
    enable_policy_signature: bool,
    accept_insecure_policies: bool,
) -> Result<Box<Service>, String> {
    match Service::new(
        primary_private_key,
        /*secondary_private_key*/ None,
        policies,
        enable_policy_signature,
        accept_insecure_policies,
    ) {
        Ok(service) => Ok(Box::new(service)),
        Err(error) => Err(error),
    }
}

pub fn new_service_with_second_key(
    primary_private_key: &[u8],
    secondary_private_key: &[u8],
    policies: &[u8],
    enable_policy_signature: bool,
    accept_insecure_policies: bool,
) -> Result<Box<Service>, String> {
    match Service::new(
        primary_private_key,
        Some(secondary_private_key),
        policies,
        enable_policy_signature,
        accept_insecure_policies,
    ) {
        Ok(service) => Ok(Box::new(service)),
        Err(error) => Err(error),
    }
}

impl Service {
    pub fn new(
        primary_private_key: &[u8],
        secondary_private_key: Option<&[u8]>,
        policies: &[u8],
        enable_policy_signature: bool,
        accept_insecure_policies: bool,
    ) -> Result<Self, String> {
        let primary_private_key_scalar: P256Scalar =
            primary_private_key.try_into().map_err(|_| {
                format!(
                    "Invalid primary private key. Key should be {P256_SCALAR_LENGTH} bytes long."
                )
            })?;

        let (secondary_public_key, secondary_private_key_scalar) = if secondary_private_key
            .is_some()
        {
            // Using `unwrap()` since we already check `is_some()` is true above.
            let key_scalar : P256Scalar = secondary_private_key.unwrap().try_into().map_err(|_| {
            format!("Invalid secondary private key. Key should be {P256_SCALAR_LENGTH} bytes long.")
        })?;
            (Some(key_scalar.compute_public_key()), Some(key_scalar))
        } else {
            (None, None)
        };

        let policy_manager =
            PolicyManager::new(policies, enable_policy_signature, accept_insecure_policies)?;

        Ok(Self {
            primary_public_key: primary_private_key_scalar.compute_public_key(),
            primary_private_key: primary_private_key_scalar,
            secondary_private_key: secondary_private_key_scalar,
            secondary_public_key: secondary_public_key,
            policy_manager,
        })
    }

    pub fn create_request_handler(&self, time_milis: i64, user: &str) -> Box<RequestHandler> {
        Box::new(RequestHandler::new(
            time_milis,
            &self.primary_private_key,
            &self.primary_public_key,
            self.secondary_private_key.as_ref(),
            self.secondary_public_key.as_ref(),
            &self.policy_manager,
            user,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::privacy_sandbox::tvs::{
        attest_report_request, attest_report_response, stage0_measurement, AmdSev,
        AppraisalPolicies, AppraisalPolicy, AttestReportRequest, AttestReportResponse,
        InitSessionRequest, Measurement, Secret, Signature as PolicySignature, Stage0Measurement,
        VerifyReportRequest, VerifyReportRequestEncrypted, VerifyReportResponse,
    };
    use crypto::P256Scalar;
    use handshake::noise::HandshakeType;
    use oak_proto_rust::oak::attestation::v1::{InsecureReferenceValues, TcbVersion};
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use prost::Message;

    fn get_good_evidence() -> oak_proto_rust::oak::attestation::v1::Evidence {
        oak_proto_rust::oak::attestation::v1::Evidence::decode(
            include_bytes!("../test_data/good_evidence.binarypb").as_slice(),
        )
        .expect("could not decode evidence")
    }

    fn get_genoa_vcek() -> Vec<u8> {
        include_bytes!("../test_data/vcek_genoa.crt").to_vec()
    }

    fn default_appraisal_policies() -> Vec<u8> {
        let policies = AppraisalPolicies {
            policies: vec![AppraisalPolicy{
                measurement: Some(Measurement {
                    stage0_measurement: Some(Stage0Measurement{
                        r#type: Some(stage0_measurement::Type::AmdSev(AmdSev{
                            sha384: "de654ed1eb03b69567338d357f86735c64fc771676bcd5d05ca6afe86f3eb9f7549222afae6139a8d282a34d09d59f95".to_string(),
                            min_tcb_version: Some(TcbVersion{
                                boot_loader: 7,
                                microcode: 62,
                                snp: 15,
                                tee: 0,
                            }),
                        })),
                    }),
                    kernel_image_sha256: "442a36913e2e299da2b516814483b6acef11b63e03f735610341a8561233f7bf".to_string(),
                    kernel_setup_data_sha256: "68cb426afaa29465f7c71f26d4f9ab5a82c2e1926236648bec226a8194431db9".to_string(),
                    init_ram_fs_sha256: "3b30793d7f3888742ad63f13ebe6a003bc9b7634992c6478a6101f9ef323b5ae".to_string(),
                    memory_map_sha256: "4c985428fdc6101c71cc26ddc313cd8221bcbc54471991ec39b1be026d0e1c28".to_string(),
                    acpi_table_sha256: "a4df9d8a64dcb9a713cec028d70d2b1599faef07ccd0d0e1816931496b4898c8".to_string(),
                    kernel_cmd_line_regex: "^ console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=10000000 brd.max_part=1 ip=10.0.2.15:::255.255.255.0::eth0:off$".to_string(),
                    system_image_sha256: "e3ded9e7cfd953b4ee6373fb8b412a76be102a6edd4e05aa7f8970e20bfc4bcd".to_string(),
                    container_binary_sha256:"bf173d846c64e5caf491de9b5ea2dfac349cfe22a5e6f03ad8048bb80ade430c".to_string(),

                }),
                signature: vec![PolicySignature{
                    signature: "003cfc8524266b283d4381e967680765bbd2a9ac2598eb256ba82ba98b3e23b384e72ad846c4ec3ff7b0791a53011b51d5ec1f61f61195ff083c4a97d383c13c".to_string(),
                    signer: "".to_string(),
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
                    kernel_image_sha256: "442a36913e2e299da2b516814483b6acef11b63e03f735610341a8561233f7bf".to_string(),
                    kernel_setup_data_sha256: "68cb426afaa29465f7c71f26d4f9ab5a82c2e1926236648bec226a8194431db9".to_string(),
                    init_ram_fs_sha256: "3b30793d7f3888742ad63f13ebe6a003bc9b7634992c6478a6101f9ef323b5ae".to_string(),
                    memory_map_sha256: "4c985428fdc6101c71cc26ddc313cd8221bcbc54471991ec39b1be026d0e1c28".to_string(),
                    acpi_table_sha256: "a4df9d8a64dcb9a713cec028d70d2b1599faef07ccd0d0e1816931496b4898c8".to_string(),
                    kernel_cmd_line_regex: "^ console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=10000000 brd.max_part=1 ip=10.0.2.15:::255.255.255.0::eth0:off$".to_string(),
                    system_image_sha256: "e3ded9e7cfd953b4ee6373fb8b412a76be102a6edd4e05aa7f8970e20bfc4bcd".to_string(),
                    container_binary_sha256:"bf173d846c64e5caf491de9b5ea2dfac349cfe22a5e6f03ad8048bb80ade430c".to_string(),

                }),
                signature: vec![PolicySignature{
                    signature: "6870ebf5f55debe04cd66d47ea3b2a878edd436aba59be30b1f52478bb4e12e4d40c223664ee3c0f13ce27e159bc8e7726cce52520f4fb171d6622a26169dcb6".to_string(),
                    signer: "".to_string(),
                    },
                    ],
            }],
        };
        let mut buf: Vec<u8> = Vec::with_capacity(1024);
        policies.encode(&mut buf).unwrap();
        buf
    }

    // Get client keys where the public key is registered in the test key fetcher.
    fn get_good_client_private_key() -> P256Scalar {
        static TEST_CLIENT_PRIVATE_KEY: &'static str =
            "750fa48f4ddaf3201d4f1d2139878abceeb84b09dc288c17e606640eb56437a2";
        return hex::decode(TEST_CLIENT_PRIVATE_KEY)
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();
    }

    fn hash_and_sign(handshake_hash: &[u8], signing_key: &[u8]) -> Result<Vec<u8>, String> {
        let signing_key = SigningKey::from_slice(signing_key)
            .map_err(|msg| format!("Failed to parse signing keys. {}", msg))?;
        let signature: Signature = signing_key.sign(handshake_hash);
        Ok(signature.to_vec())
    }

    fn expected_verify_report_response(user_id: i64) -> VerifyReportResponse {
        VerifyReportResponse {
            secrets: vec![Secret {
                key_id: 64,
                public_key: format!("{user_id}-public-key").into(),
                private_key: format!("{user_id}-secret").into(),
            }],
        }
    }

    fn create_attest_report_request(
        handshake: Vec<u8>,
        tvs_public_key: &[u8],
        client_public_key: &[u8],
    ) -> Result<Vec<u8>, String> {
        // Test initial handshake.
        let message = AttestReportRequest {
            request: Some(attest_report_request::Request::InitSessionRequest(
                InitSessionRequest {
                    client_message: handshake,
                    tvs_public_key: tvs_public_key.to_vec(),
                    client_public_key: client_public_key.to_vec(),
                },
            )),
        };
        let mut message_bin: Vec<u8> = Vec::with_capacity(256);
        message
            .encode(&mut message_bin)
            .map_err(|error| format!("Failed to serialize AttestReportRequest. {}", error))?;
        Ok(message_bin)
    }

    const NOW_UTC_MILLIS: i64 = 1698829200000;

    #[test]
    fn verify_report_successful() {
        key_fetcher::ffi::register_echo_key_fetcher_for_test();
        let tvs_private_key = P256Scalar::generate();
        let service = Service::new(
            &tvs_private_key.bytes(),
            /*secondary_private_key=*/ None,
            &default_appraisal_policies(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        )
        .unwrap();

        let mut request_handler = service.create_request_handler(NOW_UTC_MILLIS, "test_user1");
        let client_private_key = get_good_client_private_key();
        let mut client = handshake::client::HandshakeInitiator::new(
            HandshakeType::Kk,
            &tvs_private_key.compute_public_key(),
            Some(client_private_key.bytes()),
        );

        // Ask TVS to do its handshake part
        let handshake_bin = request_handler
            .verify_report(
                create_attest_report_request(
                    client.build_initial_message().unwrap(),
                    &tvs_private_key.compute_public_key(),
                    &client_private_key.compute_public_key(),
                )
                .unwrap()
                .as_slice(),
            )
            .unwrap();

        let message_reponse: AttestReportResponse =
            AttestReportResponse::decode(handshake_bin.as_slice()).unwrap();
        let handshake_response = match &message_reponse.response {
            Some(attest_report_response::Response::InitSessionResponse(init_session)) => {
                init_session.response_for_client.clone()
            }
            _ => panic!("Wrong response"),
        };

        let (handshake_hash, mut client_crypter) = client
            .process_response(handshake_response.as_slice())
            .unwrap();

        // Test report verification.
        let signing_key =
            hex::decode("cf8d805ed629f4f95d20714a847773b3e53d3d8ab155e52c882646f702a98ce8")
                .unwrap();
        let signature = hash_and_sign(&handshake_hash, signing_key.as_slice()).unwrap();

        let mut verify_report_request_bin: Vec<u8> = Vec::with_capacity(256);
        VerifyReportRequest {
            evidence: Some(get_good_evidence()),
            tee_certificate: get_genoa_vcek(),
            signature: signature,
        }
        .encode(&mut verify_report_request_bin)
        .unwrap();

        let encrypted_report = client_crypter
            .encrypt(verify_report_request_bin.as_slice())
            .unwrap();
        let message = AttestReportRequest {
            request: Some(attest_report_request::Request::VerifyReportRequest(
                VerifyReportRequestEncrypted {
                    client_message: encrypted_report,
                },
            )),
        };

        let mut message_bin: Vec<u8> = Vec::with_capacity(256);
        message.encode(&mut message_bin).unwrap();

        // Get the report.
        let secret_bin = request_handler
            .verify_report(message_bin.as_slice())
            .unwrap();
        let message_reponse: AttestReportResponse =
            AttestReportResponse::decode(secret_bin.as_slice()).unwrap();

        let report_response = match &message_reponse.response {
            Some(attest_report_response::Response::VerifyReportResponse(report_response)) => {
                report_response.response_for_client.clone()
            }
            _ => panic!("Wrong response"),
        };

        let secret = client_crypter.decrypt(report_response.as_slice()).unwrap();
        let response = VerifyReportResponse::decode(secret.as_slice()).unwrap();
        assert_eq!(response, expected_verify_report_response(/*user_id=*/ 1));
    }

    #[test]
    fn service_creation_error() {
        key_fetcher::ffi::register_echo_key_fetcher_for_test();
        match Service::new(
            &[1, 2, 3],
            /*secondary_private_key=*/ None,
            default_appraisal_policies().as_slice(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        ) {
            Ok(_) => assert!(false, "Service::new() should fail."),
            Err(e) => assert_eq!(
                e,
                format!(
                    "Invalid primary private key. Key should be {P256_SCALAR_LENGTH} bytes long."
                )
            ),
        }

        match Service::new(
            &[b'f'; P256_SCALAR_LENGTH * 3],
            /*secondary_private_key=*/ None,
            default_appraisal_policies().as_slice(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        ) {
            Ok(_) => assert!(false, "Service::new() should fail."),
            Err(e) => assert_eq!(
                e,
                format!(
                    "Invalid primary private key. Key should be {P256_SCALAR_LENGTH} bytes long."
                )
            ),
        }

        match Service::new(
            &P256Scalar::generate().bytes(),
            Some(&[1, 3]),
            default_appraisal_policies().as_slice(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        ) {
            Ok(_) => assert!(false, "Service::new() should fail."),
            Err(e) => assert_eq!(
                e,
                format!(
                    "Invalid secondary private key. Key should be {P256_SCALAR_LENGTH} bytes long."
                )
            ),
        }

        match Service::new(
            &P256Scalar::generate().bytes(),
            /*secondary_private_key=*/ None,
            &[1, 2, 3],
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        ) {
            Ok(_) => assert!(false, "Service::new() should fail."),
            Err(e) => assert_eq!(e, "Failed to decode (serialize) appraisal policy.",),
        }

        // Appraisal policies that accept reports from insecure hardware are rejected.
        match Service::new(
            &P256Scalar::generate().bytes(),
            /*secondary_private_key=*/ None,
            insecure_appraisal_policies().as_slice(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        ) {
            Ok(_) => assert!(false, "Service::new() should fail."),
            Err(e) => assert_eq!(e, "Cannot accept insecure policies"),
        }
    }
}
