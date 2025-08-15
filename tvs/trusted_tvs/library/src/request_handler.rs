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
use oak_proto_rust::oak::attestation::v1::Evidence;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use prost::Message;
use trusted_tvs_types::{EvidenceValidator, KeyProvider};
use tvs_proto::pcit::tvs::{
    attest_report_request, attest_report_response, AttestReportRequest, AttestReportResponse,
    InitSessionResponse, VerifyReportRequest, VerifyReportResponseEncrypted,
};

/// Process requests from a single client session.
///
/// Attestation verification is a multiple step operation.
/// Each session should be handled with the same RequestHandler.
/// RequestHandler should not be used for multiple session.
/// The attestation verification operation consists of the following:
/// 1. Establish an encrypted channel: the module uses noise KK to make
///    ensure that the channel is end-to-end encrypted. This step
///    also includes authenticating the client.
/// 2. Validate the attestation report signatures, and check measurements
///    against the appraisal policies. Note that the client needs to prove
///    that the report is generated from the same VM that sent the report
///    by asking the client to sign the handshake hash with the report's
///    application private key.
pub struct RequestHandler {
    time_milis: i64,
    primary_private_key: Arc<P256Scalar>,
    primary_public_key: [u8; P256_X962_LENGTH],
    secondary_private_key: Option<Arc<P256Scalar>>,
    secondary_public_key: Option<[u8; P256_X962_LENGTH]>,
    crypter: Option<handshake::Crypter>,
    handshake_hash: [u8; SHA256_OUTPUT_LEN],
    evidence_validator: Arc<dyn EvidenceValidator>,
    key_provider: Arc<dyn KeyProvider>,
    // Authenticated user if any.
    #[allow(dead_code)]
    user: String,
    user_id: Option<Vec<u8>>,
    terminated: bool,
}

impl RequestHandler {
    /// Create a new RequestHandler.  The function takes the following
    /// parameters:
    /// time_milis: the current time to be passed to Oak's attestation
    /// verification library. The time is currently ignored in the verification
    /// library.
    /// primary_private_key: the primary private key used in the noise channel.
    /// primary_public_key: public part of the primary_private_key.
    /// secondary_private_key: a secondary key to be used in noise channel.
    /// The key is optional and might only be used during rotation.
    /// secondary_public_key: the public part of the secondary private key.
    /// policy_manager: an object to check measurements against the appraisal
    /// policies.
    /// key_provider: an object that implements `KeyProvider` trait. The object
    /// is used to fetch TVS private keys, and clients secrets.
    /// user: username from other authentication mechanism e.g. GCP.
    /// the user is ignored for now.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        time_milis: i64,
        primary_private_key: Arc<P256Scalar>,
        primary_public_key: &[u8; P256_X962_LENGTH],
        secondary_private_key: Option<Arc<P256Scalar>>,
        secondary_public_key: Option<&[u8; P256_X962_LENGTH]>,
        evidence_validator: Arc<dyn EvidenceValidator>,
        key_provider: Arc<dyn KeyProvider>,
        user: &str,
    ) -> Self {
        Self {
            time_milis,
            primary_private_key,
            primary_public_key: *primary_public_key,
            secondary_private_key,
            secondary_public_key: secondary_public_key.copied(),
            evidence_validator,
            key_provider,
            crypter: None,
            handshake_hash: [0; SHA256_OUTPUT_LEN],
            user: String::from(user),
            user_id: None,
            terminated: false,
        }
    }

    /// Process a verify report message from the client. Based on the type of
    /// the message, the right operation is performed. The returned type is
    /// a serialized proto.
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
        self.evidence_validator.check_evidence(
            self.time_milis,
            &evidence,
            verify_report_request.tee_certificate.as_slice(),
        )?;

        let Some(ref user_id) = self.user_id else {
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

    /// Check if the session should be terminated. The session is terminated
    /// if one of the following is satisfied:
    /// 1. The client performed the handshake and provided the attestation
    ///    report.
    /// 2. The request failed for any reason.
    pub fn is_terminated(&self) -> bool {
        self.terminated
    }

    /// Get the handshake hash. This is used to identify the current session.
    pub fn handshake_hash(&self) -> Vec<u8> {
        self.handshake_hash.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::P256Scalar;
    use oak_proto_rust::oak::attestation::v1::TcbVersion;
    use policy_manager::PolicyManager;
    use tvs_proto::pcit::tvs::{
        stage0_measurement, AmdSev, AppraisalPolicies, AppraisalPolicy, InitSessionRequest,
        Measurement, Signature as PolicySignature, Stage0Measurement,
    };
    use tvs_trusted_client::TvsClient;

    fn get_evidence_v1_genoa() -> Vec<u8> {
        include_bytes!("../../../test_data/evidence_v1_genoa.binarypb").to_vec()
    }

    fn get_evidence_v2_genoa() -> Vec<u8> {
        include_bytes!("../../../test_data/evidence_v2_genoa.binarypb").to_vec()
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
                            sha384: "c57729018b0a6fb90dc17bb138b0aa35e4401004283ff4a2c24d3739ff3750f52384370e77b7032862a08c440a9bc4dc".to_string(),
                            min_tcb_version: Some(TcbVersion{
                                boot_loader: 10,
                                microcode: 84,
                                snp: 25,
                                tee: 0,
                                fmc: 0,
                            }),
                        })),
                    }),
                    kernel_image_sha256: "f9d0584247b46cc234a862aa8cd08765b38405022253a78b9af189c4cedbe447".to_string(),
                    kernel_setup_data_sha256: "75f091da89ce81e9decb378c3b72a948aed5892612256b3a6e8305ed034ec39a".to_string(),
                    init_ram_fs_sha256: "b2b5eda097c2e15988fd3837145432e3792124dbe0586edd961efda497274391".to_string(),
                    memory_map_sha256: "11103720aab9f4eff4b68b7573b6968e3947e5d7552ace7cebacdbdb448b68fe".to_string(),
                    acpi_table_sha256: "194afdde1699c335fdd4ed99fd36d9500230fbda0ab14f6d95fc35d219ddf32e".to_string(),
                    kernel_cmd_line_regex: "^ console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=10485760 brd.max_part=1 ip=10.0.2.15:::255.255.255.0::enp0s1:off quiet -- --launcher-addr=vsock://2:.*$".to_string(),
                    system_image_sha256: "3c59bd10c2b890ff152cc57fdca0633693acbb04982da90c670de6530fa8a836".to_string(),
                    container_binary_sha256:vec!["b0803886a6e096bf1c9eacaa77dd1514134d2e88a7734af9ba2dbf650884f899".to_string()],

                }),
                signature: vec![PolicySignature{
                    signature: "db07413c03902c54275858269fb19aac96ba5d80f027653bc2664a87c37c277407bffa411e6b06de773cee60fd5bb7a0f7a01eda746fa8a508bbc2bdfd83c3b6".to_string(),
                    signer: "".to_string(),
                    },
                    ],
            }],
            stage0_binary_sha256_to_blob: Default::default(),
        };
        let mut buf: Vec<u8> = Vec::with_capacity(1024);
        policies.encode(&mut buf).unwrap();
        buf
    }

    fn default_appraisal_policies_multiple_container_binaries() -> Vec<u8> {
        let policies = AppraisalPolicies {
            policies: vec![AppraisalPolicy{
                description: "Test AMD-SNP measurements".to_string(),
                measurement: Some(Measurement {
                    stage0_measurement: Some(Stage0Measurement{
                        r#type: Some(stage0_measurement::Type::AmdSev(AmdSev{
                            sha384: "c57729018b0a6fb90dc17bb138b0aa35e4401004283ff4a2c24d3739ff3750f52384370e77b7032862a08c440a9bc4dc".to_string(),
                            min_tcb_version: Some(TcbVersion{
                                boot_loader: 10,
                                microcode: 84,
                                snp: 25,
                                tee: 0,
                                fmc: 0,
                            }),
                        })),
                    }),
                    kernel_image_sha256: "f9d0584247b46cc234a862aa8cd08765b38405022253a78b9af189c4cedbe447".to_string(),
                    kernel_setup_data_sha256: "75f091da89ce81e9decb378c3b72a948aed5892612256b3a6e8305ed034ec39a".to_string(),
                    init_ram_fs_sha256: "b2b5eda097c2e15988fd3837145432e3792124dbe0586edd961efda497274391".to_string(),
                    memory_map_sha256: "11103720aab9f4eff4b68b7573b6968e3947e5d7552ace7cebacdbdb448b68fe".to_string(),
                    acpi_table_sha256: "194afdde1699c335fdd4ed99fd36d9500230fbda0ab14f6d95fc35d219ddf32e".to_string(),
                    kernel_cmd_line_regex: "^ console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=10485760 brd.max_part=1 ip=10.0.2.15:::255.255.255.0::enp0s1:off quiet -- --launcher-addr=vsock://2:.*$".to_string(),
                    system_image_sha256: "3c59bd10c2b890ff152cc57fdca0633693acbb04982da90c670de6530fa8a836".to_string(),
                    container_binary_sha256:vec!["b0803886a6e096bf1c9eacaa77dd1514134d2e88a7734af9ba2dbf650884f899".to_string(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string()],

                }),
                signature: vec![PolicySignature{
                    signature: "253879b00ed106485940dbb0abd0c2b8d08b1cdd0a25b4537265f24c5dca36b5908c87728e0a8e7a3d0c97f534d4d517c029ee2a16fb6dc98801f5b50c618fb3".to_string(),
                    signer: "".to_string(),
                    },
                    ],
            }],
            stage0_binary_sha256_to_blob: Default::default(),
        };
        let mut buf: Vec<u8> = Vec::with_capacity(1024);
        policies.encode(&mut buf).unwrap();
        buf
    }

    // should fail everytime
    fn default_appraisal_policies_no_container_binaries() -> Vec<u8> {
        let policies = AppraisalPolicies {
            policies: vec![AppraisalPolicy{
                description: "Test AMD-SNP measurements".to_string(),
                measurement: Some(Measurement {
                    stage0_measurement: Some(Stage0Measurement{
                        r#type: Some(stage0_measurement::Type::AmdSev(AmdSev{
                            sha384: "c57729018b0a6fb90dc17bb138b0aa35e4401004283ff4a2c24d3739ff3750f52384370e77b7032862a08c440a9bc4dc".to_string(),
                            min_tcb_version: Some(TcbVersion{
                                boot_loader: 10,
                                microcode: 84,
                                snp: 25,
                                tee: 0,
                                fmc: 0,
                            }),
                        })),
                    }),
                    kernel_image_sha256: "f9d0584247b46cc234a862aa8cd08765b38405022253a78b9af189c4cedbe447".to_string(),
                    kernel_setup_data_sha256: "75f091da89ce81e9decb378c3b72a948aed5892612256b3a6e8305ed034ec39a".to_string(),
                    init_ram_fs_sha256: "b2b5eda097c2e15988fd3837145432e3792124dbe0586edd961efda497274391".to_string(),
                    memory_map_sha256: "11103720aab9f4eff4b68b7573b6968e3947e5d7552ace7cebacdbdb448b68fe".to_string(),
                    acpi_table_sha256: "194afdde1699c335fdd4ed99fd36d9500230fbda0ab14f6d95fc35d219ddf32e".to_string(),
                    kernel_cmd_line_regex: "^ console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=10000000 brd.max_part=1 ip=10.0.2.15:::255.255.255.0::eth0:off$".to_string(),
                    system_image_sha256: "b0f34de77126561d911e0687f79eaad808b0948e0a1045f7449274efc2e411c5".to_string(),
                    container_binary_sha256:vec![],

                }),
                signature: vec![PolicySignature{
                    signature: "273dd08d4f420e1aeaf7ed1ab3e40c364d33fa59a18119d06500db00de92b3032c0198fa331c4506f29a76545b17ad588f2e27bd3819a5ab040a756b7ee4b21c".to_string(),
                    signer: "".to_string(),
                    },
                    ],
            }],
            stage0_binary_sha256_to_blob: Default::default(),
        };
        let mut buf: Vec<u8> = Vec::with_capacity(1024);
        policies.encode(&mut buf).unwrap();
        buf
    }

    const NOW_UTC_MILLIS: i64 = 1698829200000;

    struct TestKeyFetcher {
        user_id: Vec<u8>,
        user_authentication_public_key: [u8; P256_X962_LENGTH],
        secret: Vec<u8>,
    }

    impl KeyProvider for TestKeyFetcher {
        fn get_primary_private_key(&self) -> anyhow::Result<Vec<u8>> {
            anyhow::bail!("unimplemented.")
        }

        fn get_secondary_private_key(&self) -> Option<anyhow::Result<Vec<u8>>> {
            None
        }

        fn user_id_for_authentication_key(
            &self,
            user_authentication_public_key: &[u8],
        ) -> anyhow::Result<Vec<u8>> {
            if self.user_authentication_public_key != user_authentication_public_key {
                anyhow::bail!("Unauthenticated, provided public key is not registered");
            }
            Ok(self.user_id.clone())
        }

        fn get_secrets_for_user_id(&self, user_id: &[u8]) -> anyhow::Result<Vec<u8>> {
            if self.user_id != user_id {
                let user_id_str = std::str::from_utf8(user_id).map_err(|_| {
                    anyhow::anyhow!("Failed to get secret for user ID: {:?}", user_id)
                })?;
                anyhow::bail!("Failed to get secret for user ID: {user_id_str}");
            }
            Ok(self.secret.to_vec())
        }
    }

    fn init_logger() {
        // https://docs.rs/env_logger/0.9.1/env_logger/#capturing-logs-in-tests
        let _ = env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::max())
            .try_init();
    }

    #[test]
    fn verify_report_successful() {
        init_logger();
        let tvs_private_key = P256Scalar::generate();
        let tvs_public_key = tvs_private_key.compute_public_key();
        let policy_manager = PolicyManager::new_with_policies(
            default_appraisal_policies().as_slice(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        )
        .unwrap();
        let user_id = b"1";
        let client_private_key = P256Scalar::generate();
        let secret = b"secret1";
        let test_key_fetcher = TestKeyFetcher {
            user_id: user_id.to_vec(),
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

        let mut tvs_client = TvsClient::new(&client_private_key.bytes(), &tvs_public_key).unwrap();

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
                        &get_evidence_v1_genoa(),
                        &get_genoa_vcek(),
                        /*application_signing_key=*/
                        "be828103ab28b93a5d91592d69374541d6e7decd287ef7df1f990a87f231cb8c",
                    )
                    .unwrap(),
            )
            .unwrap();

        assert_eq!(
            tvs_client.process_response(secret_bin.as_slice()).unwrap(),
            secret
        );
    }

    #[test]
    fn verify_report_successful_multiple_container_binaries() {
        init_logger();
        let tvs_private_key = P256Scalar::generate();
        let tvs_public_key = tvs_private_key.compute_public_key();
        let policy_manager = PolicyManager::new_with_policies(
            default_appraisal_policies_multiple_container_binaries().as_slice(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        )
        .unwrap();
        let user_id = b"1";
        let client_private_key = P256Scalar::generate();
        let secret = b"secret1";
        let test_key_fetcher = TestKeyFetcher {
            user_id: user_id.to_vec(),
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

        let mut tvs_client = TvsClient::new(&client_private_key.bytes(), &tvs_public_key).unwrap();

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
                        &get_evidence_v1_genoa(),
                        &get_genoa_vcek(),
                        /*application_signing_key=*/
                        "be828103ab28b93a5d91592d69374541d6e7decd287ef7df1f990a87f231cb8c",
                    )
                    .unwrap(),
            )
            .unwrap();

        assert_eq!(
            tvs_client.process_response(secret_bin.as_slice()).unwrap(),
            secret
        );
    }

    #[test]
    fn verify_report_with_secondary_key_successful() {
        init_logger();
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

        let user_id = b"2";
        let client_private_key = P256Scalar::generate();
        let secret = b"secret2";
        let test_key_fetcher = TestKeyFetcher {
            user_id: user_id.to_vec(),
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

        let mut tvs_client =
            TvsClient::new(&client_private_key.bytes(), &secondary_tvs_public_key).unwrap();

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
                        &get_evidence_v1_genoa(),
                        &get_genoa_vcek(),
                        /*application_signing_key=*/
                        "be828103ab28b93a5d91592d69374541d6e7decd287ef7df1f990a87f231cb8c",
                    )
                    .unwrap(),
            )
            .unwrap();

        assert_eq!(
            tvs_client.process_response(secret_bin.as_slice()).unwrap(),
            secret
        );
    }

    // Test that the handshake session is terminated after the first
    // VerifyReportRequest regardless of the success status.
    #[test]
    fn verify_report_session_termination_on_successful_session() {
        init_logger();
        let tvs_private_key = P256Scalar::generate();
        let tvs_public_key = tvs_private_key.compute_public_key();
        let policy_manager = PolicyManager::new_with_policies(
            default_appraisal_policies().as_slice(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        )
        .unwrap();

        let user_id = b"3";
        let client_private_key = P256Scalar::generate();
        let secret = b"secret3";
        let test_key_fetcher = TestKeyFetcher {
            user_id: user_id.to_vec(),
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

        let mut tvs_client = TvsClient::new(&client_private_key.bytes(), &tvs_public_key).unwrap();

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
                        &get_evidence_v1_genoa(),
                        &get_genoa_vcek(),
                        /*application_signing_key=*/
                        "be828103ab28b93a5d91592d69374541d6e7decd287ef7df1f990a87f231cb8c",
                    )
                    .unwrap(),
            )
            .unwrap();

        assert_eq!(
            tvs_client.process_response(secret_bin.as_slice()).unwrap(),
            secret
        );

        // Send the attestation report again.
        match request_handler.verify_report(
            &tvs_client
                .build_verify_report_request(
                    &get_evidence_v1_genoa(),
                    &get_genoa_vcek(),
                    /*application_signing_key=*/
                    "be828103ab28b93a5d91592d69374541d6e7decd287ef7df1f990a87f231cb8c",
                )
                .unwrap(),
        ) {
            Ok(_) => panic!("verify_command() should fail."),
            Err(e) => assert!(e.to_string().contains("The session is terminated.")),
        }

        // Try to initiate the handshake session again.
        match request_handler.verify_report(&tvs_client.build_initial_message().unwrap()) {
            Ok(_) => panic!("verify_command() should fail."),
            Err(e) => assert!(e.to_string().contains("The session is terminated.")),
        }
    }

    #[test]
    fn verify_report_invalid_report_error() {
        init_logger();
        let tvs_private_key = P256Scalar::generate();
        let tvs_public_key = tvs_private_key.compute_public_key();
        let policy_manager = PolicyManager::new_with_policies(
            default_appraisal_policies().as_slice(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        )
        .unwrap();

        let user_id = b"4";
        let client_private_key = P256Scalar::generate();
        let secret = b"secret4";
        let test_key_fetcher = TestKeyFetcher {
            user_id: user_id.to_vec(),
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

        let mut tvs_client = TvsClient::new(&client_private_key.bytes(), &tvs_public_key).unwrap();

        // Ask TVS to do its handshake part
        let handshake_response = request_handler
            .verify_report(&tvs_client.build_initial_message().unwrap())
            .unwrap();

        tvs_client
            .process_handshake_response(&handshake_response)
            .unwrap();

        // Send an attestation report whose measurements do not match any of
        // the appraisal policies.
        match request_handler.verify_report(
            &tvs_client
                .build_verify_report_request(
                    &get_evidence_v2_genoa(),
                    &get_genoa_vcek(),
                    /*application_signing_key=*/
                    "90c6593892237eb36a525902340c02a6865a13e37ed9eb73b5123b312a0bb3b0",
                )
                .unwrap(),
        ) {
            Ok(_) => panic!("verify_command() should fail."),
            Err(e) => {
                assert!(e
                    .to_string()
                    .contains("Failed to verify report. No matching appraisal policy found"))
            }
        }

        // Make sure the session is terminated if the attestation request failed.
        match request_handler.verify_report(
            &tvs_client
                .build_verify_report_request(
                    &get_evidence_v2_genoa(),
                    &get_genoa_vcek(),
                    /*application_signing_key=*/
                    "be828103ab28b93a5d91592d69374541d6e7decd287ef7df1f990a87f231cb8c",
                )
                .unwrap(),
        ) {
            Ok(_) => panic!("verify_command() should fail."),
            Err(e) => assert!(e.to_string().contains("The session is terminated.")),
        }
    }

    #[test]
    fn verify_report_invalid_report_error_no_container_binaries() {
        init_logger();
        let tvs_private_key = P256Scalar::generate();
        let tvs_public_key = tvs_private_key.compute_public_key();
        let policy_manager = PolicyManager::new_with_policies(
            default_appraisal_policies_no_container_binaries().as_slice(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        )
        .unwrap();

        let user_id = b"4";
        let client_private_key = P256Scalar::generate();
        let secret = b"secret4";
        let test_key_fetcher = TestKeyFetcher {
            user_id: user_id.to_vec(),
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

        let mut tvs_client = TvsClient::new(&client_private_key.bytes(), &tvs_public_key).unwrap();

        // Ask TVS to do its handshake part
        let handshake_response = request_handler
            .verify_report(&tvs_client.build_initial_message().unwrap())
            .unwrap();

        tvs_client
            .process_handshake_response(&handshake_response)
            .unwrap();

        // Send an attestation report whose measurements do not match any of
        // the appraisal policies.
        match request_handler.verify_report(
            &tvs_client
                .build_verify_report_request(
                    &get_evidence_v2_genoa(),
                    &get_genoa_vcek(),
                    /*application_signing_key=*/
                    "90c6593892237eb36a525902340c02a6865a13e37ed9eb73b5123b312a0bb3b0",
                )
                .unwrap(),
        ) {
            Ok(_) => panic!("verify_command() should fail."),
            Err(e) => {
                assert!(e
                    .to_string()
                    .contains("Failed to verify report. No matching appraisal policy found"))
            }
        }

        // Make sure the session is terminated if the attestation request failed.
        match request_handler.verify_report(
            &tvs_client
                .build_verify_report_request(
                    &get_evidence_v2_genoa(),
                    &get_genoa_vcek(),
                    /*application_signing_key=*/
                    "90c6593892237eb36a525902340c02a6865a13e37ed9eb73b5123b312a0bb3b0",
                )
                .unwrap(),
        ) {
            Ok(_) => panic!("verify_command() should fail."),
            Err(e) => assert!(e.to_string().contains("The session is terminated.")),
        }
    }

    #[test]
    fn verify_report_system_layer_verification_error() {
        init_logger();
        let tvs_private_key = P256Scalar::generate();
        let tvs_public_key = tvs_private_key.compute_public_key();
        let policy_manager = PolicyManager::new_with_policies(
            default_appraisal_policies().as_slice(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        )
        .unwrap();

        let user_id = b"5";
        let client_private_key = P256Scalar::generate();
        let secret = b"secret5";
        let test_key_fetcher = TestKeyFetcher {
            user_id: user_id.to_vec(),
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

        let mut tvs_client = TvsClient::new(&client_private_key.bytes(), &tvs_public_key).unwrap();

        // Ask TVS to do its handshake part
        let handshake_response = request_handler
            .verify_report(&tvs_client.build_initial_message().unwrap())
            .unwrap();

        tvs_client
            .process_handshake_response(&handshake_response)
            .unwrap();

        match request_handler.verify_report(
            &tvs_client
                .build_verify_report_request(
                    &get_evidence_v2_genoa(),
                    &get_genoa_vcek(),
                    /*application_signing_key=*/
                    "90c6593892237eb36a525902340c02a6865a13e37ed9eb73b5123b312a0bb3b0",
                )
                .unwrap(),
        ) {
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
        init_logger();
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

        let user_id = b"6";
        let client_private_key = P256Scalar::generate();
        let secret = b"secret6";
        let test_key_fetcher = TestKeyFetcher {
            user_id: user_id.to_vec(),
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

        let mut tvs_client =
            TvsClient::new(&client_private_key.bytes(), &secondary_tvs_public_key).unwrap();

        // Ask TVS to perform its handshake part and expect it to fail as it does not recognize
        // the public key the client used.
        match request_handler.verify_report(&tvs_client.build_initial_message().unwrap()) {
            Ok(_) => panic!("verify_report() should fail."),
            Err(e) => assert_eq!(e.to_string(), "Unknown public key"),
        }
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

    #[test]
    fn verify_report_unauthenticated_error() {
        init_logger();
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

        let user_id = b"7";
        let client_private_key = P256Scalar::generate();
        let secret = b"secret7";
        let test_key_fetcher = Arc::new(TestKeyFetcher {
            user_id: user_id.to_vec(),
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
            policy_manager.clone(),
            test_key_fetcher.clone(),
            "test_user1",
        );

        // Use a private key whose public counter-part is not registered in the
        // TVS.
        let mut tvs_client =
            TvsClient::new(&P256Scalar::generate().bytes(), &tvs_public_key).unwrap();

        // Ask TVS to do its handshake part
        match request_handler.verify_report(&tvs_client.build_initial_message().unwrap()) {
            Ok(_) => panic!("verify_report() should fail."),
            Err(e) => assert_eq!(
                e.to_string(),
                "Unauthenticated, provided public key is not registered",
            ),
        };

        // Test that requests where requests with client public key in the proto doesn't match
        // the one used in the handshake fail.
        let mut request_handler = RequestHandler::new(
            NOW_UTC_MILLIS,
            tvs_private_key.clone(),
            &tvs_public_key,
            /*secondary_private_key=*/ None,
            /*secondary_public_key=*/ None,
            policy_manager.clone(),
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
            policy_manager.clone(),
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
        init_logger();
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

        let user_id = b"8";
        let client_private_key = P256Scalar::generate();
        let secret = b"secret8";
        let test_key_fetcher = Arc::new(TestKeyFetcher {
            user_id: user_id.to_vec(),
            user_authentication_public_key: client_private_key.compute_public_key(),
            secret: secret.to_vec(),
        });
        let mut request_handler = RequestHandler::new(
            NOW_UTC_MILLIS,
            tvs_private_key.clone(),
            &tvs_public_key,
            /*secondary_private_key=*/ None,
            /*secondary_public_key=*/ None,
            policy_manager.clone(),
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
            policy_manager.clone(),
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
        init_logger();
        let tvs_private_key = P256Scalar::generate();
        let tvs_public_key = tvs_private_key.compute_public_key();

        let policy_manager = PolicyManager::new_with_policies(
            default_appraisal_policies().as_slice(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        )
        .unwrap();

        let user_id = b"9";
        let client_private_key = P256Scalar::generate();
        let secret = b"secret9";
        let test_key_fetcher = TestKeyFetcher {
            user_id: user_id.to_vec(),
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
