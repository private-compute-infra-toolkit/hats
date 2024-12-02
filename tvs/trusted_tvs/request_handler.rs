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

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use anyhow::Context;
use crypto::{P256Scalar, P256_X962_LENGTH, SHA256_OUTPUT_LEN};
use handshake::noise::HandshakeType;
use key_provider::KeyProvider;
use oak_proto_rust::oak::attestation::v1::Evidence;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use policy_manager::PolicyManager;
use prost::Message;
use tvs_proto::privacy_sandbox::tvs::{
    attest_report_request, attest_report_response, AttestReportRequest, AttestReportResponse,
    InitSessionResponse, VerifyReportRequest, VerifyReportResponseEncrypted,
};

pub struct RequestHandler {
    time_milis: i64,
    primary_private_key: Arc<P256Scalar>,
    primary_public_key: [u8; P256_X962_LENGTH],
    secondary_private_key: Option<Arc<P256Scalar>>,
    secondary_public_key: Option<[u8; P256_X962_LENGTH]>,
    crypter: Option<handshake::Crypter>,
    handshake_hash: [u8; SHA256_OUTPUT_LEN],
    policy_manager: Arc<PolicyManager>,
    key_provider: Arc<dyn KeyProvider>,
    // Authenticated user if any.
    #[allow(dead_code)]
    user: String,
    user_id: Option<i64>,
    terminated: bool,
}

impl RequestHandler {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        time_milis: i64,
        primary_private_key: Arc<P256Scalar>,
        primary_public_key: &[u8; P256_X962_LENGTH],
        secondary_private_key: Option<Arc<P256Scalar>>,
        secondary_public_key: Option<&[u8; P256_X962_LENGTH]>,
        policy_manager: Arc<PolicyManager>,
        key_provider: Arc<dyn KeyProvider>,
        user: &str,
    ) -> Self {
        Self {
            time_milis,
            primary_private_key,
            primary_public_key: *primary_public_key,
            secondary_private_key,
            secondary_public_key: secondary_public_key.copied(),
            policy_manager,
            key_provider,
            crypter: None,
            handshake_hash: [0; SHA256_OUTPUT_LEN],
            user: String::from(user),
            user_id: None,
            terminated: false,
        }
    }

    pub fn verify_report(&mut self, request: &[u8]) -> anyhow::Result<Vec<u8>> {
        if self.is_terminated() {
            anyhow::bail!("The session is terminated.");
        }
        let request = AttestReportRequest::decode(request)
            .map_err(|_| anyhow::anyhow!("Failed to decode (serialize) AttestReportRequest."))?;
        let response = self.attest_report_internal(&request)?;
        let mut buf: Vec<u8> = Vec::with_capacity(1024);
        response.encode(&mut buf).map_err(|_| {
            anyhow::anyhow!(
                "Failed to encode AttestReportRequest. Something must have gone wrong internally."
            )
        })?;
        Ok(buf)
    }

    fn attest_report_internal(
        &mut self,
        request: &AttestReportRequest,
    ) -> anyhow::Result<AttestReportResponse> {
        match &request.request {
            Some(attest_report_request::Request::InitSessionRequest(init_session)) => {
                let ephemeral_pubkey = self.do_init_session(
                    init_session.client_message.as_slice(),
                    init_session.tvs_public_key.as_slice(),
                    init_session.client_public_key.as_slice(),
                )?;
                Ok(AttestReportResponse {
                    response: Some(attest_report_response::Response::InitSessionResponse(
                        InitSessionResponse {
                            response_for_client: ephemeral_pubkey,
                        },
                    )),
                })
            }
            Some(attest_report_request::Request::VerifyReportRequest(verify_report)) => {
                let secret = self.do_verify_report(verify_report.client_message.as_slice());
                self.terminate();
                match secret {
                    Ok(secret) => Ok(AttestReportResponse {
                        response: Some(attest_report_response::Response::VerifyReportResponse(
                            VerifyReportResponseEncrypted {
                                response_for_client: secret,
                            },
                        )),
                    }),
                    Err(err) => Err(err),
                }
            }
            None => anyhow::bail!("AttestReportRequest is malformed"),
        }
    }

    // Given a public key, return the private counter part.
    fn private_key_to_use(&self, public_key: &[u8]) -> anyhow::Result<&P256Scalar> {
        if public_key == self.primary_public_key {
            return Ok(&self.primary_private_key);
        }
        let Some(secondary_public_key) = self.secondary_public_key else {
            anyhow::bail!("Unknown public key");
        };
        if public_key != secondary_public_key {
            anyhow::bail!("Unknown public key");
        }
        match &self.secondary_private_key {
            Some(secondary_private_key) => Ok(secondary_private_key),
            None => anyhow::bail!("Internal error, no secondary key"),
        }
    }

    fn do_init_session(
        &mut self,
        handshake_request: &[u8],
        public_key: &[u8],
        client_public_key: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        if self.crypter.is_some() {
            anyhow::bail!("Handshake has already been made.");
        }
        let private_key = self.private_key_to_use(public_key)?;
        // First check if we recognize the public key.
        let user_id = self
            .key_provider
            .user_id_for_authentication_key(client_public_key)?;

        let handshake_response = handshake::respond(
            HandshakeType::Kk,
            private_key,
            public_key,
            Some(client_public_key),
            handshake_request,
            /*prologue=*/ &[public_key, client_public_key].concat(),
        )
        .map_err(|_| anyhow::anyhow!("Invalid handshake."))?;

        self.crypter = Some(handshake_response.crypter);
        self.handshake_hash = handshake_response.handshake_hash;
        self.user_id = Some(user_id);
        Ok(handshake_response.response)
    }

    fn check_report_and_encrypt_secret(
        &mut self,
        verify_report_request: VerifyReportRequest,
    ) -> anyhow::Result<Vec<u8>> {
        let Some(evidence) = verify_report_request.evidence else {
            anyhow::bail!("Request does not have `evidence` proto.");
        };
        self.validate_signature(&evidence, verify_report_request.signature.as_slice())?;
        self.policy_manager.check_evidence(
            self.time_milis,
            &evidence,
            verify_report_request.tee_certificate.as_slice(),
        )?;

        let Some(user_id) = self.user_id else {
            // This should not happen unless something went wrong internally
            // such as this method is called out of order or the logic that sets user id
            // was changed.
            anyhow::bail!("Something went wrong. user_id has no value.");
        };

        let secret = self.key_provider.get_secrets_for_user_id(user_id)?;

        if self.crypter.is_none() {
            // This should not happen unless something went wrong internally
            // such as this method is called out of order.
            anyhow::bail!("Something went wrong. crypter is not initialized.");
        }
        match self.crypter.as_mut().unwrap().encrypt(&secret) {
            Ok(cipher_text) => Ok(cipher_text),
            Err(_) => anyhow::bail!("Failed to encrypt message."),
        }
    }

    fn do_verify_report(&mut self, report: &[u8]) -> anyhow::Result<Vec<u8>> {
        let Some(crypter) = &mut self.crypter else {
            anyhow::bail!("A successful handshake is require prior to process any request.");
        };
        let clear_text = crypter
            .decrypt(report)
            .map_err(|_| anyhow::anyhow!("Failed to decrypt request."))?;
        let verify_report_request = VerifyReportRequest::decode(clear_text.as_slice())
            .map_err(|_| anyhow::anyhow!("Failed to decode (serialize) request proto"))?;
        self.check_report_and_encrypt_secret(verify_report_request)
    }

    fn validate_signature(&self, evidence: &Evidence, signature: &[u8]) -> anyhow::Result<()> {
        // oak_attestation_verification::extract::extract_evidence::verify() returns
        // the same proto that includes the parsed application keys; however, we want
        // to verify signatures before we validate the certificate (to early reject invalid requests).
        // Extracting application keys require some processing as they are represented as a CBOR
        // certificate, which contains claims and other values.
        let extracted_evidence = oak_attestation_verification::extract::extract_evidence(evidence)
            .context("extracting evidence")?;
        // .map_err(|msg| format!("Failed to extract evidence {}", msg))?;
        let signature = Signature::from_slice(signature)
            .map_err(|err| anyhow::anyhow!("Failed to parse signature. {err}"))?;
        let verifying_key =
            VerifyingKey::from_sec1_bytes(extracted_evidence.signing_public_key.as_slice())
                .map_err(|err| {
                    anyhow::anyhow!(
                        "Failed to de-serialize application signing key from evidence. {err}",
                    )
                })?;
        verifying_key
            .verify(&self.handshake_hash, &signature)
            .map_err(|msg| anyhow::anyhow!("Signature does not match. {}", msg))
    }

    // Drop crypter and handshake hash to force clients to re-initiate the session.
    fn terminate(&mut self) {
        self.crypter = None;
        self.handshake_hash = [0; SHA256_OUTPUT_LEN];
        self.terminated = true;
    }

    pub fn is_terminated(&self) -> bool {
        self.terminated
    }

    pub fn handshake_hash(&self) -> Vec<u8> {
        self.handshake_hash.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::P256Scalar;
    use oak_proto_rust::oak::attestation::v1::TcbVersion;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use tvs_proto::privacy_sandbox::tvs::{
        stage0_measurement, AmdSev, AppraisalPolicies, AppraisalPolicy, InitSessionRequest,
        Measurement, Signature as PolicySignature, Stage0Measurement, VerifyReportRequestEncrypted,
    };

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

    fn get_malformed_evidence() -> oak_proto_rust::oak::attestation::v1::Evidence {
        oak_proto_rust::oak::attestation::v1::Evidence::decode(
            include_bytes!("../test_data/malformed_evidence.binarypb").as_slice(),
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

    fn hash_and_sign(handshake_hash: &[u8], signing_key: &[u8]) -> anyhow::Result<Vec<u8>> {
        let signing_key = SigningKey::from_slice(signing_key)
            .map_err(|msg| anyhow::anyhow!("Failed to parse signing keys. {}", msg))?;
        let signature: Signature = signing_key.sign(handshake_hash);
        Ok(signature.to_vec())
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

    struct TestKeyFetcher {
        user_id: i64,
        user_authentication_public_key: [u8; P256_X962_LENGTH],
        secret: Vec<u8>,
    }

    impl key_provider::KeyProvider for TestKeyFetcher {
        fn get_primary_private_key(&self) -> anyhow::Result<Vec<u8>> {
            anyhow::bail!("unimplemented.")
        }

        fn get_secondary_private_key(&self) -> Option<anyhow::Result<Vec<u8>>> {
            None
        }

        fn user_id_for_authentication_key(
            &self,
            user_authentication_public_key: &[u8],
        ) -> anyhow::Result<i64> {
            if self.user_authentication_public_key != user_authentication_public_key {
                anyhow::bail!("Unauthenticated, provided public key is not registered");
            }
            Ok(self.user_id)
        }

        fn get_secrets_for_user_id(&self, user_id: i64) -> anyhow::Result<Vec<u8>> {
            if self.user_id != user_id {
                anyhow::bail!("Failed to get secret for user ID: {user_id}");
            }
            Ok(self.secret.to_vec())
        }
    }

    #[test]
    fn verify_report_successful() {
        let tvs_private_key = P256Scalar::generate();
        let tvs_public_key = tvs_private_key.compute_public_key();
        let policy_manager = PolicyManager::new_with_policies(
            default_appraisal_policies().as_slice(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        )
        .unwrap();
        let user_id = 1;
        let client_private_key = P256Scalar::generate();
        let secret = b"secret1";
        let test_key_fetcher = TestKeyFetcher {
            user_id,
            user_authentication_public_key: client_private_key.compute_public_key(),
            secret: secret.to_vec(),
        };

        let mut request_handler = RequestHandler::new(
            NOW_UTC_MILLIS,
            Arc::new(tvs_private_key),
            &tvs_public_key,
            /*secondary_private_key=*/ None,
            /*secondary_public_key=*/ None,
            Arc::new(policy_manager),
            Arc::new(test_key_fetcher),
            "test_user1",
        );

        let mut client = handshake::client::HandshakeInitiator::new(
            HandshakeType::Kk,
            &tvs_public_key,
            Some(client_private_key.bytes()),
        );
        // Ask TVS to do its handshake part
        let handshake_bin = request_handler
            .verify_report(
                create_attest_report_request(
                    client.build_initial_message().unwrap(),
                    &tvs_public_key,
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
            signature,
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

        assert_eq!(
            client_crypter.decrypt(report_response.as_slice()).unwrap(),
            secret
        );
    }

    #[test]
    fn verify_report_with_secondary_key_successful() {
        let primary_tvs_private_key = P256Scalar::generate();
        let primary_tvs_public_key = primary_tvs_private_key.compute_public_key();
        let secondary_tvs_private_key = P256Scalar::generate();
        let secondary_tvs_public_key = secondary_tvs_private_key.compute_public_key();
        let policy_manager = PolicyManager::new_with_policies(
            default_appraisal_policies().as_slice(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        )
        .unwrap();

        let user_id = 2;
        let client_private_key = P256Scalar::generate();
        let secret = b"secret2";
        let test_key_fetcher = TestKeyFetcher {
            user_id,
            user_authentication_public_key: client_private_key.compute_public_key(),
            secret: secret.to_vec(),
        };

        let mut request_handler = RequestHandler::new(
            NOW_UTC_MILLIS,
            Arc::new(primary_tvs_private_key),
            &primary_tvs_public_key,
            Some(Arc::new(secondary_tvs_private_key)),
            Some(&secondary_tvs_public_key),
            Arc::new(policy_manager),
            Arc::new(test_key_fetcher),
            "test_user2",
        );

        let mut client = handshake::client::HandshakeInitiator::new(
            HandshakeType::Kk,
            &secondary_tvs_public_key,
            Some(client_private_key.bytes()),
        );

        // Ask TVS to do its handshake part
        let handshake_bin = request_handler
            .verify_report(
                create_attest_report_request(
                    client.build_initial_message().unwrap(),
                    &secondary_tvs_public_key,
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
            signature,
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

        assert_eq!(
            client_crypter.decrypt(report_response.as_slice()).unwrap(),
            secret
        );
    }

    // Test that the handshake session is terminated after the first
    // VerifyReportRequest regardless of the success status.
    #[test]
    fn verify_report_session_termination_on_successful_session() {
        let tvs_private_key = P256Scalar::generate();
        let tvs_public_key = tvs_private_key.compute_public_key();
        let policy_manager = PolicyManager::new_with_policies(
            default_appraisal_policies().as_slice(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        )
        .unwrap();

        let user_id = 3;
        let client_private_key = P256Scalar::generate();
        let secret = b"secret3";
        let test_key_fetcher = TestKeyFetcher {
            user_id,
            user_authentication_public_key: client_private_key.compute_public_key(),
            secret: secret.to_vec(),
        };
        let mut request_handler = RequestHandler::new(
            NOW_UTC_MILLIS,
            Arc::new(tvs_private_key),
            &tvs_public_key,
            /*secondary_private_key=*/ None,
            /*secondary_public_key=*/ None,
            Arc::new(policy_manager),
            Arc::new(test_key_fetcher),
            "test_user1",
        );

        let mut client = handshake::client::HandshakeInitiator::new(
            HandshakeType::Kk,
            &tvs_public_key,
            Some(client_private_key.bytes()),
        );

        // Ask TVS to do its handshake part
        let handshake_bin = request_handler
            .verify_report(
                create_attest_report_request(
                    client.build_initial_message().unwrap(),
                    &tvs_public_key,
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
            signature,
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

        assert_eq!(
            client_crypter.decrypt(report_response.as_slice()).unwrap(),
            secret
        );

        match request_handler.verify_report(message_bin.as_slice()) {
            Ok(_) => panic!("verify_command() should fail."),
            Err(e) => assert!(e.to_string().contains("The session is terminated.")),
        }

        match request_handler.verify_report(
            create_attest_report_request(
                client.build_initial_message().unwrap(),
                &tvs_public_key,
                &client_private_key.compute_public_key(),
            )
            .unwrap()
            .as_slice(),
        ) {
            Ok(_) => panic!("verify_command() should fail."),
            Err(e) => assert!(e.to_string().contains("The session is terminated.")),
        }
    }

    #[test]
    fn verify_report_invalid_report_error() {
        let tvs_private_key = P256Scalar::generate();
        let tvs_public_key = tvs_private_key.compute_public_key();
        let policy_manager = PolicyManager::new_with_policies(
            default_appraisal_policies().as_slice(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        )
        .unwrap();

        let user_id = 4;
        let client_private_key = P256Scalar::generate();
        let secret = b"secret4";
        let test_key_fetcher = TestKeyFetcher {
            user_id,
            user_authentication_public_key: client_private_key.compute_public_key(),
            secret: secret.to_vec(),
        };
        let mut request_handler = RequestHandler::new(
            NOW_UTC_MILLIS,
            Arc::new(tvs_private_key),
            &tvs_public_key,
            /*secondary_private_key=*/ None,
            /*secondary_public_key=*/ None,
            Arc::new(policy_manager),
            Arc::new(test_key_fetcher),
            "test_user",
        );

        let mut client = handshake::client::HandshakeInitiator::new(
            HandshakeType::Kk,
            &tvs_public_key,
            Some(client_private_key.bytes()),
        );
        // Ask TVS to do its handshake part
        let handshake_bin = request_handler
            .verify_report(
                create_attest_report_request(
                    client.build_initial_message().unwrap(),
                    &tvs_public_key,
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
        let mut verify_report_request_bin: Vec<u8> = Vec::with_capacity(256);
        VerifyReportRequest {
            evidence: Some(get_malformed_evidence()),
            tee_certificate: get_genoa_vcek(),
            signature: hash_and_sign(&handshake_hash, signing_key.as_slice()).unwrap(),
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
        let mut message_bin: Vec<u8> = Vec::with_capacity(256);
        message.encode(&mut message_bin).unwrap();

        match request_handler.verify_report(message_bin.as_slice()) {
            Ok(_) => panic!("verify_command() should fail."),
            Err(e) => {
                assert!(e
                    .to_string()
                    .contains("Failed to verify report. No matching appraisal policy found"))
            }
        }

        match request_handler.verify_report(message_bin.as_slice()) {
            Ok(_) => panic!("verify_command() should fail."),
            Err(e) => assert!(e.to_string().contains("The session is terminated.")),
        }
    }

    #[test]
    fn verify_report_system_layer_verification_error() {
        let tvs_private_key = P256Scalar::generate();
        let tvs_public_key = tvs_private_key.compute_public_key();
        let policy_manager = PolicyManager::new_with_policies(
            default_appraisal_policies().as_slice(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        )
        .unwrap();

        let user_id = 5;
        let client_private_key = P256Scalar::generate();
        let secret = b"secret5";
        let test_key_fetcher = TestKeyFetcher {
            user_id,
            user_authentication_public_key: client_private_key.compute_public_key(),
            secret: secret.to_vec(),
        };
        let mut request_handler = RequestHandler::new(
            NOW_UTC_MILLIS,
            Arc::new(tvs_private_key),
            &tvs_public_key,
            /*secondary_private_key=*/ None,
            /*secondary_public_key=*/ None,
            Arc::new(policy_manager),
            Arc::new(test_key_fetcher),
            "test_user",
        );

        let mut client = handshake::client::HandshakeInitiator::new(
            HandshakeType::Kk,
            &tvs_public_key,
            Some(client_private_key.bytes()),
        );
        // Ask TVS to do its handshake part
        let handshake_bin = request_handler
            .verify_report(
                create_attest_report_request(
                    client.build_initial_message().unwrap(),
                    &tvs_public_key,
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
            hex::decode("df2eb4193f689c0fd5a266d764b8b6fd28e584b4f826a3ccb96f80fed2949759")
                .unwrap();
        let mut verify_report_request_bin: Vec<u8> = Vec::with_capacity(256);
        VerifyReportRequest {
            evidence: Some(get_bad_evidence()),
            tee_certificate: get_genoa_vcek(),
            signature: hash_and_sign(&handshake_hash, signing_key.as_slice()).unwrap(),
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

        match request_handler.verify_report(message_bin.as_slice()) {
            Ok(_) => panic!("verify_command() should fail."),
            Err(e) => {
                assert!(e
                    .to_string()
                    .contains("Failed to verify report. No matching appraisal policy found"))
            }
        }
    }

    #[test]
    fn verify_report_unknown_public_key_error() {
        let primary_tvs_private_key = P256Scalar::generate();
        let primary_tvs_public_key = primary_tvs_private_key.compute_public_key();
        let secondary_tvs_private_key = P256Scalar::generate();
        let secondary_tvs_public_key = secondary_tvs_private_key.compute_public_key();
        let policy_manager = PolicyManager::new_with_policies(
            default_appraisal_policies().as_slice(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        )
        .unwrap();

        let user_id = 6;
        let client_private_key = P256Scalar::generate();
        let secret = b"secret6";
        let test_key_fetcher = TestKeyFetcher {
            user_id,
            user_authentication_public_key: client_private_key.compute_public_key(),
            secret: secret.to_vec(),
        };
        let mut request_handler = RequestHandler::new(
            NOW_UTC_MILLIS,
            Arc::new(primary_tvs_private_key),
            &primary_tvs_public_key,
            /*secondary_private_key=*/ None,
            /*secondary_public_key=*/ None,
            Arc::new(policy_manager),
            Arc::new(test_key_fetcher),
            "test_user",
        );

        let mut client = handshake::client::HandshakeInitiator::new(
            HandshakeType::Kk,
            &secondary_tvs_public_key,
            Some(client_private_key.bytes()),
        );

        match request_handler.verify_report(
            create_attest_report_request(
                client.build_initial_message().unwrap(),
                &secondary_tvs_public_key,
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
    fn verify_report_unauthenticated_error() {
        let tvs_private_key = Arc::new(P256Scalar::generate());
        let tvs_public_key = tvs_private_key.compute_public_key();
        // Test that unregistered client keys are rejected.
        let policy_manager = Arc::new(
            PolicyManager::new_with_policies(
                default_appraisal_policies().as_slice(),
                /*enable_policy_signature=*/ true,
                /*accept_insecure_policies=*/ false,
            )
            .unwrap(),
        );

        let user_id = 7;
        let client_private_key = P256Scalar::generate();
        let secret = b"secret7";
        let test_key_fetcher = Arc::new(TestKeyFetcher {
            user_id,
            user_authentication_public_key: client_private_key.compute_public_key(),
            secret: secret.to_vec(),
        });

        // Test that unregistered client keys are rejected.
        let mut request_handler = RequestHandler::new(
            NOW_UTC_MILLIS,
            tvs_private_key.clone(),
            &tvs_public_key,
            /*secondary_private_key=*/ None,
            /*secondary_public_key=*/ None,
            Arc::clone(&policy_manager),
            test_key_fetcher.clone(),
            "test_user1",
        );

        let mut client = handshake::client::HandshakeInitiator::new(
            HandshakeType::Kk,
            &tvs_private_key.compute_public_key(),
            Some(P256Scalar::generate().bytes()),
        );

        // Ask TVS to do its handshake part
        match request_handler.verify_report(
            create_attest_report_request(
                client.build_initial_message().unwrap(),
                &tvs_public_key,
                &P256Scalar::generate().compute_public_key(),
            )
            .unwrap()
            .as_slice(),
        ) {
            Ok(_) => panic!("verify_report() should fail."),
            Err(e) => assert_eq!(
                e.to_string(),
                "Unauthenticated, provided public key is not registered",
            ),
        }

        // Test that requests where requests with client public key in the proto doesn't match
        // the one used in the handshake fail.
        let mut request_handler = RequestHandler::new(
            NOW_UTC_MILLIS,
            tvs_private_key.clone(),
            &tvs_public_key,
            /*secondary_private_key=*/ None,
            /*secondary_public_key=*/ None,
            Arc::clone(&policy_manager),
            test_key_fetcher.clone(),
            "test_user1",
        );

        let mut client = handshake::client::HandshakeInitiator::new(
            HandshakeType::Kk,
            &tvs_private_key.compute_public_key(),
            Some(P256Scalar::generate().bytes()),
        );

        // Ask TVS to do its handshake part
        match request_handler.verify_report(
            create_attest_report_request(
                client.build_initial_message().unwrap(),
                &tvs_public_key,
                &client_private_key.compute_public_key(),
            )
            .unwrap()
            .as_slice(),
        ) {
            Ok(_) => panic!("verify_report() should fail."),
            Err(e) => assert_eq!(e.to_string(), "Invalid handshake."),
        }

        // Test that clients using Nk are rejected.
        let mut request_handler = RequestHandler::new(
            NOW_UTC_MILLIS,
            tvs_private_key.clone(),
            &tvs_public_key,
            /*secondary_private_key=*/ None,
            /*secondary_public_key=*/ None,
            Arc::clone(&policy_manager),
            test_key_fetcher.clone(),
            "test_user1",
        );

        let mut client = handshake::client::HandshakeInitiator::new(
            HandshakeType::Nk,
            &tvs_private_key.compute_public_key(),
            None,
        );

        // Ask TVS to do its handshake part
        match request_handler.verify_report(
            create_attest_report_request(
                client.build_initial_message().unwrap(),
                &tvs_public_key,
                &client_private_key.compute_public_key(),
            )
            .unwrap()
            .as_slice(),
        ) {
            Ok(_) => panic!("verify_report() should fail."),
            Err(e) => assert_eq!(e.to_string(), "Invalid handshake."),
        }
    }

    #[test]
    fn handshake_error() {
        let tvs_private_key = Arc::new(P256Scalar::generate());
        let tvs_public_key = tvs_private_key.compute_public_key();
        let policy_manager = Arc::new(
            PolicyManager::new_with_policies(
                default_appraisal_policies().as_slice(),
                /*enable_policy_signature=*/ true,
                /*accept_insecure_policies=*/ false,
            )
            .unwrap(),
        );

        let user_id = 8;
        let client_private_key = P256Scalar::generate();
        let secret = b"secret8";
        let test_key_fetcher = Arc::new(TestKeyFetcher {
            user_id,
            user_authentication_public_key: client_private_key.compute_public_key(),
            secret: secret.to_vec(),
        });
        let mut request_handler = RequestHandler::new(
            NOW_UTC_MILLIS,
            tvs_private_key.clone(),
            &tvs_public_key,
            /*secondary_private_key=*/ None,
            /*secondary_public_key=*/ None,
            Arc::clone(&policy_manager),
            test_key_fetcher.clone(),
            "test_user",
        );

        // Test invalid initiator handshake error.
        match request_handler.do_init_session(
            b"ab",
            &tvs_public_key,
            &client_private_key.compute_public_key(),
        ) {
            Ok(_) => panic!("do_init_session() should fail."),
            Err(e) => assert_eq!(e.to_string(), "Invalid handshake.".to_string()),
        }

        let mut request_handler = RequestHandler::new(
            NOW_UTC_MILLIS,
            tvs_private_key.clone(),
            &tvs_public_key,
            /*secondary_private_key=*/ None,
            /*secondary_public_key=*/ None,
            Arc::clone(&policy_manager),
            test_key_fetcher.clone(),
            "test_user",
        );

        let client_handshake = handshake::client::HandshakeInitiator::new(
            HandshakeType::Kk,
            &tvs_private_key.compute_public_key(),
            Some(client_private_key.bytes()),
        )
        .build_initial_message()
        .unwrap();
        assert!(request_handler
            .do_init_session(
                client_handshake.as_slice(),
                &tvs_public_key,
                &client_private_key.compute_public_key(),
            )
            .is_ok());
        // Test duplicate initiator handshake error.
        match request_handler.do_init_session(
            client_handshake.as_slice(),
            &tvs_public_key,
            &client_private_key.compute_public_key(),
        ) {
            Ok(_) => panic!("do_init_session() should fail."),
            Err(e) => assert_eq!(
                e.to_string(),
                "Handshake has already been made.".to_string()
            ),
        }
    }

    #[test]
    fn verify_report_error() {
        let tvs_private_key = P256Scalar::generate();
        let tvs_public_key = tvs_private_key.compute_public_key();

        let policy_manager = PolicyManager::new_with_policies(
            default_appraisal_policies().as_slice(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        )
        .unwrap();

        let user_id = 9;
        let client_private_key = P256Scalar::generate();
        let secret = b"secret9";
        let test_key_fetcher = TestKeyFetcher {
            user_id,
            user_authentication_public_key: client_private_key.compute_public_key(),
            secret: secret.to_vec(),
        };
        let mut request_handler = RequestHandler::new(
            NOW_UTC_MILLIS,
            Arc::new(tvs_private_key),
            &tvs_public_key,
            /*secondary_private_key=*/ None,
            /*secondary_public_key=*/ None,
            Arc::new(policy_manager),
            Arc::new(test_key_fetcher),
            "test_user",
        );

        match request_handler.do_verify_report(b"aaa") {
            Ok(_) => panic!("do_verify_command() should fail."),
            Err(e) => assert_eq!(
                e.to_string(),
                "A successful handshake is require prior to process any request.".to_string()
            ),
        }
    }
}
