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
extern crate alloc;
use crate::request_handler::RequestHandler;
use alloc::boxed::Box;
use alloc::sync::Arc;
use crypto::P256_SCALAR_LENGTH;
use crypto::{P256Scalar, P256_X962_LENGTH};
use policy_manager::PolicyManager;
use trusted_tvs_types::{EvidenceValidator, KeyProvider};

/// Public interface to use the crate.
///
/// Clients use this crate to create
/// a Service object that owns key materials, policies and means to fetch user
/// secrets.
pub struct Service {
    primary_private_key: Arc<P256Scalar>,
    primary_public_key: [u8; P256_X962_LENGTH],
    secondary_private_key: Option<Arc<P256Scalar>>,
    secondary_public_key: Option<[u8; P256_X962_LENGTH]>,
    key_provider: Arc<dyn KeyProvider>,
    evidence_validator: Arc<dyn EvidenceValidator>,
}

impl Service {
    /// Create a new Service object. The function takes the following
    /// parameters:
    /// key_provider: an object that implements `KeyProvider` trait. The object
    /// is used to fetch TVS private keys, and clients secrets.
    /// policies: serialized bytes of `AppraisalPolicies` to validate
    /// measurements against.
    /// enable_policy_signature: whether or not to check signature on the
    /// policies.
    /// accept_insecure_policies: whether or not to accept policies allowing
    /// measurement from non-CVM i.e. self signed reports.
    pub fn new(
        key_provider: Arc<dyn KeyProvider>,
        policies: &[u8],
        enable_policy_signature: bool,
        accept_insecure_policies: bool,
    ) -> anyhow::Result<Self> {
        let primary_private_key: P256Scalar = key_provider
            .get_primary_private_key()?
            .as_slice()
            .try_into()
            .map_err(|_| {
                anyhow::anyhow!(
                    "Invalid primary private key. Key should be {P256_SCALAR_LENGTH} bytes long."
                )
            })?;
        let secondary_private_key = key_provider.get_secondary_private_key();
        let (secondary_public_key, secondary_private_key) = if secondary_private_key.is_some() {
            // Using `unwrap()` since we already check `is_some()` is true above.
            let secondary_private_key_value: P256Scalar = secondary_private_key
                .unwrap()?
                .as_slice()
                .try_into()
                .map_err(|_| {
                    anyhow::anyhow!(
                    "Invalid secondary private key. Key should be {P256_SCALAR_LENGTH} bytes long."
                )
                })?;
            (
                Some(secondary_private_key_value.compute_public_key()),
                Some(Arc::new(secondary_private_key_value)),
            )
        } else {
            (None, None)
        };

        let policy_manager = Arc::new(PolicyManager::new_with_policies(
            policies,
            enable_policy_signature,
            accept_insecure_policies,
        )?);

        Ok(Self {
            primary_public_key: primary_private_key.compute_public_key(),
            primary_private_key: Arc::new(primary_private_key),
            secondary_private_key,
            secondary_public_key,
            evidence_validator: policy_manager,
            key_provider,
        })
    }

    /// Create `RequestHandler` object to process clients request from a single
    /// session. Note that the handler should be used for one session only.
    pub fn create_request_handler(&self, time_milis: i64, user: &str) -> Box<RequestHandler> {
        Box::new(RequestHandler::new(
            time_milis,
            self.primary_private_key.clone(),
            &self.primary_public_key,
            self.secondary_private_key.as_ref().cloned(),
            self.secondary_public_key.as_ref(),
            Arc::clone(&self.evidence_validator),
            Arc::clone(&self.key_provider),
            user,
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::interface::new_service;
    use crypto::{P256Scalar, P256_SCALAR_LENGTH};
    use handshake::noise::HandshakeType;
    use key_fetcher::ffi::create_test_key_fetcher_wrapper;
    use oak_proto_rust::oak::attestation::v1::{InsecureReferenceValues, TcbVersion};
    use prost::Message;
    use tvs_proto::privacy_sandbox::tvs::{
        attest_report_request, stage0_measurement, AmdSev, AppraisalPolicies, AppraisalPolicy,
        AttestReportRequest, InitSessionRequest, Measurement, Secret, Signature as PolicySignature,
        Stage0Measurement, VerifyReportResponse,
    };
    use tvs_trusted_client::TvsClient;

    fn get_good_evidence() -> Vec<u8> {
        include_bytes!("../../../test_data/good_evidence.binarypb").to_vec()
    }

    fn get_genoa_vcek() -> Vec<u8> {
        include_bytes!("../../../test_data/vcek_genoa.crt").to_vec()
    }

    fn default_appraisal_policies() -> Vec<u8> {
        let policies = AppraisalPolicies {
            policies: vec![AppraisalPolicy{
                description: "Test AMD-SNP measurements".to_string(),
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
                description: "Test insecure VM measurements".to_string(),
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

    fn create_attest_report_request(
        handshake: Vec<u8>,
        tvs_public_key: &[u8],
        client_public_key: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
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
        message.encode(&mut message_bin).map_err(|error| {
            anyhow::anyhow!("Failed to serialize AttestReportRequest. {}", error)
        })?;
        Ok(message_bin)
    }

    const NOW_UTC_MILLIS: i64 = 1698829200000;

    #[test]
    fn verify_report_successful() {
        let tvs_private_key = P256Scalar::generate();
        let client_private_key = P256Scalar::generate();
        let user_id = 1;
        let key_id = 11;
        let key_fetcher = create_test_key_fetcher_wrapper(
            /*primary_private_key=*/ &tvs_private_key.bytes(),
            /*secondary_private_key,*/ &[],
            user_id,
            /*user_authentication_public_key=*/ &client_private_key.compute_public_key(),
            key_id,
            /*user_secret=*/ b"test_secret1",
            /*public_key=*/ b"test_public_key1",
        );

        let service = new_service(
            key_fetcher,
            &default_appraisal_policies(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        )
        .unwrap();

        let mut request_handler = service.create_request_handler(NOW_UTC_MILLIS, "test_user1");

        let mut tvs_client = TvsClient::new(
            &client_private_key.bytes(),
            &tvs_private_key.compute_public_key(),
        )
        .unwrap();

        // Ask TVS to do its handshake part
        let handshake_response = request_handler
            .verify_report(&tvs_client.build_initial_message().unwrap())
            .unwrap();

        tvs_client
            .process_handshake_response(&handshake_response)
            .unwrap();

        // Send the attestation report and get the secrets.
        let secret_bin = request_handler
            .verify_report(
                &tvs_client
                    .build_verify_report_request(
                        &get_good_evidence(),
                        &get_genoa_vcek(),
                        /*application_signing_key=*/
                        "cf8d805ed629f4f95d20714a847773b3e53d3d8ab155e52c882646f702a98ce8",
                    )
                    .unwrap(),
            )
            .unwrap();

        let response = VerifyReportResponse::decode(
            tvs_client
                .process_response(secret_bin.as_slice())
                .unwrap()
                .as_slice(),
        )
        .unwrap();

        assert_eq!(
            response,
            VerifyReportResponse {
                secrets: vec![Secret {
                    key_id,
                    private_key: b"test_secret1".to_vec(),
                    public_key: "test_public_key1".to_string(),
                }],
            }
        );
    }

    #[test]
    fn verify_report_successful_with_secondary_key() {
        let tvs_private_key = P256Scalar::generate();
        let client_private_key = P256Scalar::generate();
        let user_id = 2;
        let key_id = 12;
        let key_fetcher = create_test_key_fetcher_wrapper(
            /*primary_private_key=*/ &P256Scalar::generate().bytes(),
            /*secondary_private_key,*/ &tvs_private_key.bytes(),
            user_id,
            /*user_authentication_public_key=*/ &client_private_key.compute_public_key(),
            key_id,
            /*user_secret=*/ b"test_secret2",
            /*public_key=*/ b"test_public_key2",
        );
        let service = new_service(
            key_fetcher,
            &default_appraisal_policies(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        )
        .unwrap();

        let mut request_handler = service.create_request_handler(NOW_UTC_MILLIS, "test_user1");

        let mut tvs_client = TvsClient::new(
            &client_private_key.bytes(),
            &tvs_private_key.compute_public_key(),
        )
        .unwrap();

        // Ask TVS to do its handshake part
        let handshake_response = request_handler
            .verify_report(&tvs_client.build_initial_message().unwrap())
            .unwrap();

        tvs_client
            .process_handshake_response(&handshake_response)
            .unwrap();

        // Send the attestation report and get the secrets.
        let secret_bin = request_handler
            .verify_report(
                &tvs_client
                    .build_verify_report_request(
                        &get_good_evidence(),
                        &get_genoa_vcek(),
                        /*application_signing_key=*/
                        "cf8d805ed629f4f95d20714a847773b3e53d3d8ab155e52c882646f702a98ce8",
                    )
                    .unwrap(),
            )
            .unwrap();

        let response = VerifyReportResponse::decode(
            tvs_client
                .process_response(secret_bin.as_slice())
                .unwrap()
                .as_slice(),
        )
        .unwrap();

        assert_eq!(
            response,
            VerifyReportResponse {
                secrets: vec![Secret {
                    key_id,
                    private_key: b"test_secret2".to_vec(),
                    public_key: "test_public_key2".to_string(),
                }],
            }
        );
    }

    #[test]
    fn verify_report_wrong_tvs_key_used_by_client() {
        // First. test that the client used the wrong key in the handshake.
        let tvs_private_key = P256Scalar::generate();
        let client_private_key = P256Scalar::generate();
        let key_fetcher = create_test_key_fetcher_wrapper(
            /*primary_private_key=*/ &tvs_private_key.bytes(),
            /*secondary_private_key,*/ &[],
            /*user_id=*/ 3,
            /*user_authentication_public_key=*/ &client_private_key.compute_public_key(),
            /*key_id=*/ 13,
            /*user_secret=*/ b"test_secret3",
            /*public_key=*/ b"test_public_key3",
        );
        let service = new_service(
            key_fetcher,
            &default_appraisal_policies(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        )
        .unwrap();

        let mut request_handler = service.create_request_handler(NOW_UTC_MILLIS, "test_user1");

        let mut client = handshake::client::HandshakeInitiator::new(
            HandshakeType::Kk,
            &P256Scalar::generate().compute_public_key(),
            Some(client_private_key.bytes()),
        );

        match request_handler.verify_report(
            create_attest_report_request(
                client.build_initial_message().unwrap(),
                &tvs_private_key.compute_public_key(),
                &client_private_key.compute_public_key(),
            )
            .unwrap()
            .as_slice(),
        ) {
            Ok(_) => panic!("verify_report() should fail."),
            Err(e) => assert_eq!(e.to_string(), format!("Invalid handshake.")),
        }

        // Second, test that client used the right key for handshake but
        // provided the wrong key in the prologue.
        let tvs_private_key = P256Scalar::generate();
        let client_private_key = P256Scalar::generate();
        let key_fetcher = create_test_key_fetcher_wrapper(
            /*primary_private_key=*/ &tvs_private_key.bytes(),
            /*secondary_private_key,*/ &[],
            /*user_id=*/ 3,
            /*user_authentication_public_key=*/ &client_private_key.compute_public_key(),
            /*key_id=*/ 13,
            /*user_secret=*/ b"test_secret3",
            /*public_key=*/ b"test_public_key3",
        );
        let service = new_service(
            key_fetcher,
            &default_appraisal_policies(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        )
        .unwrap();

        let mut request_handler = service.create_request_handler(NOW_UTC_MILLIS, "test_user1");
        let mut client = handshake::client::HandshakeInitiator::new(
            HandshakeType::Kk,
            &tvs_private_key.compute_public_key(),
            Some(client_private_key.bytes()),
        );

        match request_handler.verify_report(
            create_attest_report_request(
                client.build_initial_message().unwrap(),
                &P256Scalar::generate().compute_public_key(),
                &client_private_key.compute_public_key(),
            )
            .unwrap()
            .as_slice(),
        ) {
            Ok(_) => panic!("verify_report() should fail."),
            Err(e) => assert_eq!(e.to_string(), format!("Unknown public key")),
        }

        // Third, test that client used the wrong key for both handshake and
        // provided the wrong key in the prologue.
        let tvs_private_key = P256Scalar::generate();
        let client_private_key = P256Scalar::generate();
        let key_fetcher = create_test_key_fetcher_wrapper(
            /*primary_private_key=*/ &tvs_private_key.bytes(),
            /*secondary_private_key,*/ &[],
            /*user_id=*/ 3,
            /*user_authentication_public_key=*/ &client_private_key.compute_public_key(),
            /*key_id=*/ 13,
            /*user_secret=*/ b"test_secret3",
            /*public_key=*/ b"test_public_key3",
        );
        let service = new_service(
            key_fetcher,
            &default_appraisal_policies(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        )
        .unwrap();

        let mut request_handler = service.create_request_handler(NOW_UTC_MILLIS, "test_user1");
        let mut client = handshake::client::HandshakeInitiator::new(
            HandshakeType::Kk,
            &P256Scalar::generate().compute_public_key(),
            Some(client_private_key.bytes()),
        );

        match request_handler.verify_report(
            create_attest_report_request(
                client.build_initial_message().unwrap(),
                &P256Scalar::generate().compute_public_key(),
                &client_private_key.compute_public_key(),
            )
            .unwrap()
            .as_slice(),
        ) {
            Ok(_) => panic!("verify_report() should fail."),
            Err(e) => assert_eq!(e.to_string(), "Unknown public key"),
        }
    }

    #[test]
    fn verify_report_unrecognized_client_authentication_key() {
        // First. test that the client used the wrong key in the handshake.
        let tvs_private_key = P256Scalar::generate();
        let client_private_key = P256Scalar::generate();
        let key_fetcher = create_test_key_fetcher_wrapper(
            /*primary_private_key=*/ &tvs_private_key.bytes(),
            /*secondary_private_key,*/ &[],
            /*user_id=*/ 4,
            /*user_authentication_public_key=*/ &client_private_key.compute_public_key(),
            /*key_id=*/ 14,
            /*user_secret=*/ b"test_secret3",
            /*public_key=*/ b"test_public_key3",
        );
        let service = new_service(
            key_fetcher,
            &default_appraisal_policies(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        )
        .unwrap();

        let mut request_handler = service.create_request_handler(NOW_UTC_MILLIS, "test_user1");
        let mut client = handshake::client::HandshakeInitiator::new(
            HandshakeType::Kk,
            &tvs_private_key.compute_public_key(),
            Some(P256Scalar::generate().bytes()),
        );

        match request_handler.verify_report(
            create_attest_report_request(
                client.build_initial_message().unwrap(),
                &tvs_private_key.compute_public_key(),
                &client_private_key.compute_public_key(),
            )
            .unwrap()
            .as_slice(),
        ) {
            Ok(_) => panic!("verify_report() should fail."),
            Err(e) => assert_eq!(e.to_string(), "Invalid handshake."),
        }

        // Second, test that client used the right key for handshake but
        // provided the wrong key in the prologue.
        let tvs_private_key = P256Scalar::generate();
        let client_private_key = P256Scalar::generate();
        let key_fetcher = create_test_key_fetcher_wrapper(
            /*primary_private_key=*/ &tvs_private_key.bytes(),
            /*secondary_private_key,*/ &[],
            /*user_id=*/ 4,
            /*user_authentication_public_key=*/ &client_private_key.compute_public_key(),
            /*key_id=*/ 14,
            /*user_secret=*/ b"test_secret3",
            /*public_key=*/ b"test_public_key3",
        );
        let service = new_service(
            key_fetcher,
            &default_appraisal_policies(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        )
        .unwrap();

        let mut request_handler = service.create_request_handler(NOW_UTC_MILLIS, "test_user1");
        let mut client = handshake::client::HandshakeInitiator::new(
            HandshakeType::Kk,
            &tvs_private_key.compute_public_key(),
            Some(client_private_key.bytes()),
        );

        match request_handler.verify_report(
            create_attest_report_request(
                client.build_initial_message().unwrap(),
                &tvs_private_key.compute_public_key(),
                &P256Scalar::generate().bytes(),
            )
            .unwrap()
            .as_slice(),
        ) {
            Ok(_) => panic!("verify_report() should fail."),
            Err(e) => assert_eq!(e.to_string(), "Unauthenticated, provided public key is not registered: Failed to lookup user: UNAUTHENTICATED: unregistered or expired public key."),
        }
        // Third, test that client used the wrong key for both handshake and
        // provided the wrong key in the prologue.
        let tvs_private_key = P256Scalar::generate();
        let client_private_key = P256Scalar::generate();
        let key_fetcher = create_test_key_fetcher_wrapper(
            /*primary_private_key=*/ &tvs_private_key.bytes(),
            /*secondary_private_key,*/ &[],
            /*user_id=*/ 4,
            /*user_authentication_public_key=*/ &client_private_key.compute_public_key(),
            /*key_id=*/ 14,
            /*user_secret=*/ b"test_secret3",
            /*public_key=*/ b"test_public_key3",
        );
        let service = new_service(
            key_fetcher,
            &default_appraisal_policies(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        )
        .unwrap();

        let mut request_handler = service.create_request_handler(NOW_UTC_MILLIS, "test_user1");
        let mut client = handshake::client::HandshakeInitiator::new(
            HandshakeType::Kk,
            &tvs_private_key.compute_public_key(),
            Some(P256Scalar::generate().bytes()),
        );

        match request_handler.verify_report(
            create_attest_report_request(
                client.build_initial_message().unwrap(),
                &tvs_private_key.compute_public_key(),
                &P256Scalar::generate().bytes(),
            )
            .unwrap()
            .as_slice(),
        ) {
            Ok(_) => panic!("verify_report() should fail."),
            Err(e) => assert_eq!(e.to_string(), "Unauthenticated, provided public key is not registered: Failed to lookup user: UNAUTHENTICATED: unregistered or expired public key."),
        }
    }

    #[test]
    fn verify_report_no_secret_error() {
        let tvs_private_key = P256Scalar::generate();
        let client_private_key = P256Scalar::generate();
        let user_id = 5;
        let key_id = 15;
        let key_fetcher = create_test_key_fetcher_wrapper(
            /*primary_private_key=*/ &tvs_private_key.bytes(),
            /*secondary_private_key,*/ &[],
            user_id,
            /*user_authentication_public_key=*/ &client_private_key.compute_public_key(),
            key_id,
            /*user_secret=*/ &[],
            /*public_key=*/ &[],
        );
        let service = new_service(
            key_fetcher,
            &default_appraisal_policies(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        )
        .unwrap();

        let mut request_handler = service.create_request_handler(NOW_UTC_MILLIS, "test_user1");

        let mut tvs_client = TvsClient::new(
            &client_private_key.bytes(),
            &tvs_private_key.compute_public_key(),
        )
        .unwrap();

        // Ask TVS to do its handshake part
        let handshake_response = request_handler
            .verify_report(&tvs_client.build_initial_message().unwrap())
            .unwrap();

        tvs_client
            .process_handshake_response(&handshake_response)
            .unwrap();

        // Send the attestation report and get the secrets.
        match request_handler.verify_report(
            &tvs_client
                .build_verify_report_request(
                    &get_good_evidence(),
                    &get_genoa_vcek(),
                    /*application_signing_key=*/
                    "cf8d805ed629f4f95d20714a847773b3e53d3d8ab155e52c882646f702a98ce8",
                )
                .unwrap(),
        ) {
            Ok(_) => panic!("verify_report() should fail."),
            Err(e) => assert_eq!(
                e.to_string(),
                format!("Failed to get secret for user ID: {user_id}")
            ),
        }
    }

    #[test]
    fn service_creation_error() {
        let client_private_key = P256Scalar::generate();
        match new_service(
            create_test_key_fetcher_wrapper(
                /*primary_private_key=*/ &[0, 1, 3],
                /*secondary_private_key,*/ &[],
                /*user_id=*/ 6,
                /*user_authentication_public_key=*/ &client_private_key.compute_public_key(),
                /*key_id=*/ 16,
                /*user_secret=*/ b"test_secret6",
                /*public_key=*/ b"test_public_key6",
            ),
            &default_appraisal_policies(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        ) {
            Ok(_) => panic!("new_service() should fail."),
            Err(e) => assert_eq!(
                e.to_string(),
                format!(
                    "Invalid primary private key. Key should be {P256_SCALAR_LENGTH} bytes long."
                )
            ),
        }

        match new_service(
            create_test_key_fetcher_wrapper(
                /*primary_private_key=*/ &[b'f'; P256_SCALAR_LENGTH * 3],
                /*secondary_private_key,*/ &[],
                /*user_id=*/ 6,
                /*user_authentication_public_key=*/ &client_private_key.compute_public_key(),
                /*key_id=*/ 16,
                /*user_secret=*/ b"test_secret6",
                /*public_key=*/ b"test_public_key6",
            ),
            &default_appraisal_policies(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        ) {
            Ok(_) => panic!("new_service() should fail."),
            Err(e) => assert_eq!(
                e.to_string(),
                format!(
                    "Invalid primary private key. Key should be {P256_SCALAR_LENGTH} bytes long."
                )
            ),
        }

        match new_service(
            create_test_key_fetcher_wrapper(
                /*primary_private_key=*/ &P256Scalar::generate().bytes(),
                /*secondary_private_key,*/ &[1, 2],
                /*user_id=*/ 6,
                /*user_authentication_public_key=*/ &client_private_key.compute_public_key(),
                /*key_id=*/ 16,
                /*user_secret=*/ b"test_secret6",
                /*public_key=*/ b"test_public_key6",
            ),
            &default_appraisal_policies(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        ) {
            Ok(_) => panic!("new_service() should fail."),
            Err(e) => assert_eq!(
                e.to_string(),
                format!(
                    "Invalid secondary private key. Key should be {P256_SCALAR_LENGTH} bytes long."
                )
            ),
        }

        match new_service(
            create_test_key_fetcher_wrapper(
                /*primary_private_key=*/ &P256Scalar::generate().bytes(),
                /*secondary_private_key,*/ &[],
                /*user_id=*/ 6,
                /*user_authentication_public_key=*/ &client_private_key.compute_public_key(),
                /*key_id=*/ 16,
                /*user_secret=*/ b"test_secret6",
                /*public_key=*/ b"test_public_key6",
            ),
            /*policies=*/ &[1, 2, 3],
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        ) {
            Ok(_) => panic!("new_service() should fail."),
            Err(e) => assert_eq!(
                e.to_string(),
                "Failed to decode (serialize) appraisal policy."
            ),
        }

        // Appraisal policies that accept reports from insecure hardware are rejected.
        match new_service(
            create_test_key_fetcher_wrapper(
                /*primary_private_key=*/ &P256Scalar::generate().bytes(),
                /*secondary_private_key,*/ &[],
                /*user_id=*/ 6,
                /*user_authentication_public_key=*/ &client_private_key.compute_public_key(),
                /*key_id=*/ 16,
                /*user_secret=*/ b"test_secret6",
                /*public_key=*/ b"test_public_key6",
            ),
            &insecure_appraisal_policies(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        ) {
            Ok(_) => panic!("new_service() should fail."),
            Err(e) => assert_eq!(e.to_string(), "Cannot accept insecure policies."),
        }
    }
}
