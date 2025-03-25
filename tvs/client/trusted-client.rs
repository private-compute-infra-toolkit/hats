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

use crypto::{P256Scalar, P256_SCALAR_LENGTH, P256_X962_LENGTH, SHA256_OUTPUT_LEN};
use handshake::{client::HandshakeInitiator, noise::HandshakeType, Crypter};
use oak_proto_rust::oak::attestation::v1::Evidence;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use prost::Message;
use tvs_proto::privacy_sandbox::tvs::{
    attest_report_request, attest_report_response, AttestReportRequest, AttestReportResponse,
    InitSessionRequest, VerifyReportRequest, VerifyReportRequestEncrypted,
};

// Do not use cxx:bridge if `noffi` is enabled to avoid linking against
// C++ shared libraries, which is not available in the oak container linux.
// We use the reverse logic here as there is no way to set features in
// cxx bazel rules. By default ffi is enabled.
#[cfg(not(feature = "noffi"))]
#[cxx::bridge(namespace = "privacy_sandbox::tvs")]
#[cfg(not(feature = "noffi"))]
mod ffi {
    extern "Rust" {
        type TvsClient;

        #[cxx_name = "NewTvsClient"]
        fn new_tvs_client(private_key: &[u8], tvs_pub_key: &[u8]) -> Result<Box<TvsClient>>;

        #[cxx_name = "BuildInitialMessage"]
        fn build_initial_message(&mut self) -> Result<Vec<u8>>;

        #[cxx_name = "ProcessHandshakeResponse"]
        fn process_handshake_response(&mut self, response: &[u8]) -> Result<()>;

        #[cxx_name = "BuildVerifyReportRequest"]
        fn build_verify_report_request(
            &mut self,
            evidence_bin: &[u8],
            vcek: &[u8],
            application_signing_key: &str,
        ) -> Result<Vec<u8>>;

        #[cxx_name = "ProcessResponse"]
        fn process_response(&mut self, response: &[u8]) -> Result<Vec<u8>>;
    }
}

pub fn new_tvs_client(private_key: &[u8], tvs_public_key: &[u8]) -> Result<Box<TvsClient>, String> {
    match TvsClient::new(private_key, tvs_public_key) {
        Ok(tvs_client) => Ok(Box::new(tvs_client)),
        Err(error) => Err(error),
    }
}

pub struct TvsClient {
    handshake: HandshakeInitiator,
    crypter: Option<Crypter>,
    handshake_hash: [u8; SHA256_OUTPUT_LEN],
    private_key: P256Scalar,
    tvs_public_key: [u8; P256_X962_LENGTH],
}

impl TvsClient {
    pub fn new(private_key: &[u8], tvs_public_key: &[u8]) -> Result<Self, String> {
        let private_key_scalar: P256Scalar = private_key.try_into().map_err(|_| {
            format!("Invalid private key. Key should be {P256_SCALAR_LENGTH} bytes long.")
        })?;

        let tvs_public_key_bytes: [u8; P256_X962_LENGTH] = tvs_public_key
            .try_into()
            .map_err(|_| format!("Expected tvs_public_key to be of length {P256_X962_LENGTH}."))?;
        Ok(Self {
            handshake: HandshakeInitiator::new(
                HandshakeType::Kk,
                &tvs_public_key_bytes,
                Some(private_key_scalar.bytes()),
            ),
            crypter: None,
            handshake_hash: [0; SHA256_OUTPUT_LEN],
            private_key: private_key_scalar,
            tvs_public_key: tvs_public_key_bytes,
        })
    }

    pub fn build_initial_message(&mut self) -> Result<Vec<u8>, String> {
        let mut message_bin: Vec<u8> = Vec::with_capacity(256);
        AttestReportRequest {
            request: Some(attest_report_request::Request::InitSessionRequest(
                InitSessionRequest {
                    client_message: self
                        .handshake
                        .build_initial_message()
                        .map_err(|_| "Invalid Initialization of Handshake")?,
                    tvs_public_key: self.tvs_public_key.to_vec(),
                    client_public_key: self.private_key.compute_public_key().to_vec(),
                },
            )),
        }
        .encode(&mut message_bin)
        .map_err(|_| "Error encoding handshake initial message to AttestReportRequest proto")?;
        Ok(message_bin)
    }

    pub fn process_handshake_response(&mut self, response: &[u8]) -> Result<(), String> {
        let message_reponse: AttestReportResponse = prost::Message::decode(response)
            .map_err(|_| "Error decoding message to AttestReportResponse proto.".to_string())?;
        let handshake_response = match &message_reponse.response {
            Some(attest_report_response::Response::InitSessionResponse(init_session)) => {
                init_session.response_for_client.clone()
            }
            _ => {
                return Err("Unexpected proto message.".to_string());
            }
        };
        let (handshake_hash, crypter) = self
            .handshake
            .process_response(handshake_response.as_slice())
            .map_err(|_| "Handshake Failed")?;
        self.crypter = Some(crypter);
        self.handshake_hash = handshake_hash;
        Ok(())
    }

    pub fn build_verify_report_request(
        &mut self,
        evidence_bin: &[u8],
        vcek: &[u8],
        application_signing_key: &str,
    ) -> Result<Vec<u8>, String> {
        let signing_key = hex::decode(application_signing_key).map_err(|_| {
            "Cannot de-serialize application_siging_key. The key is expected to be in hex format"
        })?;
        let signature = hash_and_sign_evidence(&self.handshake_hash, signing_key)?;
        if let Some(crypter) = self.crypter.as_mut() {
            let evidence = Evidence::decode(evidence_bin)
                .map_err(|_| "Error decoding message to AttestReportResponse proto.".to_string())?;
            let mut message: Vec<u8> = Vec::with_capacity(256);
            VerifyReportRequest {
                evidence: Some(evidence),
                tee_certificate: vcek.to_vec(),
                signature,
            }
            .encode(&mut message)
            .map_err(|_| "Failed to encode VerifyReportRequest")?;
            match crypter.encrypt(message.as_slice()) {
                Ok(cipher) => {
                    let mut message: Vec<u8> = Vec::with_capacity(256);
                    AttestReportRequest {
                        request: Some(attest_report_request::Request::VerifyReportRequest(
                            VerifyReportRequestEncrypted {
                                client_message: cipher,
                            },
                        )),
                    }
                    .encode(&mut message)
                    .map_err(|_| "Failed to encode encrypted report to a proto".to_string())?;
                    Ok(message)
                }
                Err(_) => Err("Failed to encrypt a command.".to_string()),
            }
        } else {
            Err("Handshake initiation should be done before encrypting messages".to_string())
        }
    }

    pub fn process_response(&mut self, response: &[u8]) -> Result<Vec<u8>, String> {
        let Some(crypter) = self.crypter.as_mut() else {
            return Err(
                "Handshake initiation should be done before encrypting messages.".to_string(),
            );
        };
        let response: AttestReportResponse = prost::Message::decode(response)
            .map_err(|_| "Error decoding message to AttestReportResponse proto.".to_string())?;
        let report_response = match &response.response {
            Some(attest_report_response::Response::VerifyReportResponse(report_response)) => {
                report_response.response_for_client.clone()
            }
            _ => return Err("Unexpected proto message.".to_string()),
        };
        match crypter.decrypt(report_response.as_slice()) {
            Ok(plain_text) => Ok(plain_text),
            Err(_) => Err("Failed to decrypt ciphertext.".to_string()),
        }
    }
}

fn hash_and_sign_evidence(
    handshake_hash: &[u8; SHA256_OUTPUT_LEN],
    signing_key: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let key = SigningKey::from_slice(signing_key.as_slice())
        .map_err(|msg| format!("Cannot encode the provided signing key. {}", msg))?;
    let signature: Signature = key.sign(handshake_hash.as_slice());
    Ok(signature.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::P256Scalar;
    use key_fetcher::{ffi::create_test_key_fetcher_wrapper, KeyFetcher};
    use oak_proto_rust::oak::attestation::v1::TcbVersion;
    use std::sync::Arc;
    use tvs_proto::privacy_sandbox::tvs::{
        stage0_measurement, AmdSev, AppraisalPolicies, AppraisalPolicy, Measurement, Secret,
        Signature as PolicySignature, Stage0Measurement, VerifyReportResponse,
    };

    fn get_genoa_vcek() -> Vec<u8> {
        include_bytes!("../test_data/vcek_genoa.crt").to_vec()
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

    fn get_good_evidence() -> Vec<u8> {
        include_bytes!("../test_data/good_evidence.binarypb").to_vec()
    }

    const NOW_UTC_MILLIS: i64 = 1698829200000;

    // End to end testing: handshake, building and signing the report and decrypt the secret.
    #[test]
    fn verify_report_successful() {
        let tvs_private_key = P256Scalar::generate();
        let client_private_key = P256Scalar::generate();
        let key_id = 11;
        let key_fetcher = KeyFetcher::new(create_test_key_fetcher_wrapper(
            /*primary_private_key=*/ &tvs_private_key.bytes(),
            /*secondary_private_key,*/ &[],
            /*user_id=*/ b"1",
            /*user_authentication_public_key=*/ &client_private_key.compute_public_key(),
            key_id,
            /*user_secret=*/ b"test_secret1",
            /*public_key=*/ b"test_public_key1",
        ));
        let service = trusted_tvs::service::Service::new(
            Arc::new(key_fetcher),
            &default_appraisal_policies(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        )
        .unwrap();

        let mut tvs_request_handler = service.create_request_handler(NOW_UTC_MILLIS, "test_user1");

        let mut tvs_client = TvsClient::new(
            &client_private_key.bytes(),
            &tvs_private_key.compute_public_key(),
        )
        .unwrap();
        let initial_message = tvs_client.build_initial_message().unwrap();

        let handshake_response = tvs_request_handler
            .verify_report(initial_message.as_slice())
            .unwrap();
        tvs_client
            .process_handshake_response(&handshake_response)
            .unwrap();

        let report = tvs_client
            .build_verify_report_request(
                &get_good_evidence(),
                &get_genoa_vcek(),
                "cf8d805ed629f4f95d20714a847773b3e53d3d8ab155e52c882646f702a98ce8",
            )
            .unwrap();
        let secret = tvs_request_handler
            .verify_report(report.as_slice())
            .unwrap();

        let decrypted_secret = tvs_client.process_response(secret.as_slice()).unwrap();
        let response = VerifyReportResponse::decode(decrypted_secret.as_slice()).unwrap();
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
    fn process_handshake_response_error() {
        let tvs_private_key = P256Scalar::generate();
        let client_private_key = P256Scalar::generate();
        let mut tvs_client = TvsClient::new(
            &client_private_key.bytes(),
            &tvs_private_key.compute_public_key(),
        )
        .unwrap();
        match tvs_client.process_handshake_response(&[1, 2, 3]) {
            Ok(_) => panic!("process_handshake_response() should fail"),
            Err(e) => assert_eq!(e, "Error decoding message to AttestReportResponse proto."),
        }
        let report = AttestReportRequest {
            request: Some(
                tvs_proto::privacy_sandbox::tvs::attest_report_request::Request::VerifyReportRequest(
                    VerifyReportRequestEncrypted {
                        client_message: vec![1, 2],
                    },
                ),
            ),
        };
        let mut report_bin: Vec<u8> = Vec::with_capacity(256);
        report.encode(&mut report_bin).unwrap();
        match tvs_client.process_handshake_response(report_bin.as_slice()) {
            Ok(_) => panic!("process_handshake_response() should fail"),
            Err(e) => assert_eq!(e, "Unexpected proto message."),
        }
    }

    #[test]
    fn process_response_error() {
        let client_private_key = P256Scalar::generate();
        let tvs_private_key = P256Scalar::generate();
        let mut tvs_client = TvsClient::new(
            &client_private_key.bytes(),
            &tvs_private_key.compute_public_key(),
        )
        .unwrap();
        match tvs_client.process_response(&[1, 2, 3]) {
            Ok(_) => panic!("process_response() should fail"),
            Err(e) => assert_eq!(
                e,
                "Handshake initiation should be done before encrypting messages."
            ),
        }

        let key_id = 11;
        let key_fetcher = KeyFetcher::new(create_test_key_fetcher_wrapper(
            /*primary_private_key=*/ &tvs_private_key.bytes(),
            /*secondary_private_key,*/ &[],
            /*user_id=*/ b"1",
            /*user_authentication_public_key=*/ &client_private_key.compute_public_key(),
            key_id,
            /*user_secret=*/ b"test_secret1",
            /*public_key=*/ b"test_public_key1",
        ));
        let service = trusted_tvs::service::Service::new(
            Arc::new(key_fetcher),
            &default_appraisal_policies(),
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        )
        .unwrap();

        let mut tvs_request_handler = service.create_request_handler(NOW_UTC_MILLIS, "test_user1");

        // Perform handshake now so we get to the next error.
        let initial_message = tvs_client.build_initial_message().unwrap();

        let handshake_response = tvs_request_handler
            .verify_report(initial_message.as_slice())
            .unwrap();
        tvs_client
            .process_handshake_response(&handshake_response)
            .unwrap();

        match tvs_client.process_response(&[1, 2, 3]) {
            Ok(_) => panic!("process_response() should fail"),
            Err(e) => assert_eq!(e, "Error decoding message to AttestReportResponse proto."),
        }
        let report = AttestReportRequest {
            request: Some(
                tvs_proto::privacy_sandbox::tvs::attest_report_request::Request::VerifyReportRequest(
                    VerifyReportRequestEncrypted {
                        client_message: vec![1, 2],
                    },
                ),
            ),
        };
        let mut report_bin: Vec<u8> = Vec::with_capacity(256);
        report.encode(&mut report_bin).unwrap();
        match tvs_client.process_response(report_bin.as_slice()) {
            Ok(_) => panic!("process_response() should fail"),
            Err(e) => assert_eq!(e, "Failed to decrypt ciphertext."),
        }
    }

    #[test]
    fn new_tvs_client_error() {
        let tvs_private_key = P256Scalar::generate();
        match TvsClient::new(&[1, 2, 3], &tvs_private_key.compute_public_key()) {
            Ok(_) => panic!("TvsClient::new() should fail"),
            Err(e) => assert_eq!(e, "Invalid private key. Key should be 32 bytes long.",),
        }
        let client_private_key = P256Scalar::generate();
        match TvsClient::new(&client_private_key.bytes(), &[1, 2, 3]) {
            Ok(_) => panic!("TvsClient::new() should fail"),
            Err(e) => assert_eq!(
                e,
                format!("Expected tvs_public_key to be of length {P256_X962_LENGTH}."),
            ),
        }
    }
}
