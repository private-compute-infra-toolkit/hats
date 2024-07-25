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

// Required for prost
#![feature(never_type)]

extern crate handshake;
extern crate hex;

use crate::proto::privacy_sandbox::tvs::{
    attest_report_request, attest_report_response, AttestReportRequest, AttestReportResponse,
    InitSessionResponse, VerifyReportRequest, VerifyReportResponseEncrypted,
};
use crypto::{P256_SCALAR_LENGTH, SHA256_OUTPUT_LEN};
use oak_proto_rust::oak::attestation::v1::Evidence;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use prost::Message;

pub mod proto {
    pub mod privacy_sandbox {
        pub mod tvs {
            include!(concat!(env!("OUT_DIR"), "/privacy_sandbox.tvs.rs"));
        }
    }
}

pub struct TrustedTvs {
    time_milis: i64,
    // A big-endian P-256 private scalar, used as the Noise identity key.
    identity_private_key: [u8; P256_SCALAR_LENGTH],
    crypter: Option<handshake::Crypter>,
    handshake_hash: [u8; SHA256_OUTPUT_LEN],
    appraisal_policy: oak_proto_rust::oak::attestation::v1::ReferenceValues,
    secret: String,
    terminated: bool,
}

// Export TrustedTvs and it's methods to C++.
#[cxx::bridge(namespace = "privacy_sandbox::tvs")]
mod ffi {
    extern "Rust" {
        type TrustedTvs;

        fn new_trusted_tvs_service(
            time_milis: i64,
            private_key_in_hex_str: &str,
            policy: &[u8],
            secret: &str,
        ) -> Result<Box<TrustedTvs>>;
        pub fn verify_report(self: &mut TrustedTvs, request: &[u8]) -> Result<Vec<u8>>;
        pub fn is_terminated(self: &TrustedTvs) -> bool;
    }
}

pub fn new_trusted_tvs_service(
    time_milis: i64,
    private_key_in_hex_str: &str,
    policy: &[u8],
    secret: &str,
) -> Result<Box<TrustedTvs>, String> {
    match hex::decode(private_key_in_hex_str) {
        Ok(identity_private_key) => {
            let identity_private_key_fixed_size: [u8; P256_SCALAR_LENGTH] =
                identity_private_key.try_into().map_err(|_| {
                    format!(
                        "Invalid private key length. Key should be {} bytes long.",
                        P256_SCALAR_LENGTH
                    )
                })?;
            let appraisal_policy =
                oak_proto_rust::oak::attestation::v1::ReferenceValues::decode(policy)
                    .map_err(|_| "Failed to decode (serialize) appraisal policy.".to_string())?;
            Ok(Box::new(TrustedTvs::new(
                time_milis,
                &identity_private_key_fixed_size,
                appraisal_policy,
                secret.to_string(),
            )))
        }
        Err(_) => Err(
            "Invalid private key format. Private key should be formatted as hex string."
                .to_string(),
        ),
    }
}
impl TrustedTvs {
    fn new(
        time_milis: i64,
        identity_private_key: &[u8; P256_SCALAR_LENGTH],
        appraisal_policy: oak_proto_rust::oak::attestation::v1::ReferenceValues,
        secret: String,
    ) -> Self {
        Self {
            time_milis,
            identity_private_key: *identity_private_key,
            appraisal_policy,
            crypter: None,
            handshake_hash: [0; SHA256_OUTPUT_LEN],
            secret,
            terminated: false,
        }
    }

    pub fn verify_report(self: &mut TrustedTvs, request: &[u8]) -> Result<Vec<u8>, String> {
        if self.is_terminated() {
            return Err("The session is terminated.".to_string());
        }
        let request = AttestReportRequest::decode(request)
            .map_err(|_| "Failed to decode (serialize) AttestReportRequest.".to_string())?;
        let response = self.attest_report_internal(&request)?;
        let mut buf: Vec<u8> = Vec::with_capacity(1024);
        response.encode(&mut buf).map_err(|_| {
            "Failed to encode AttestReportRequest. Something must have gone wrong internally."
        })?;
        Ok(buf)
    }

    fn attest_report_internal(
        &mut self,
        request: &AttestReportRequest,
    ) -> Result<AttestReportResponse, String> {
        match &request.request {
            Some(attest_report_request::Request::InitSessionRequest(init_session)) => {
                let ephemeral_pubkey =
                    self.do_init_session(init_session.client_message.as_slice())?;
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
            None => Err("AttestReportRequest is malformed".to_string()),
        }
    }

    fn do_init_session(&mut self, handshake_request: &[u8]) -> Result<Vec<u8>, String> {
        if let Some(_) = &self.crypter {
            Err("Handshake has already been made.".to_string())
        } else {
            match handshake::respond(&self.identity_private_key, handshake_request) {
                Ok(r) => {
                    self.crypter = Some(r.crypter);
                    self.handshake_hash = r.handshake_hash;
                    Ok(r.response)
                }
                Err(_) => Err("Handshake has already been made.".to_string()),
            }
        }
    }

    fn check_report_and_encrypt_secret(
        &mut self,
        verify_report_request: VerifyReportRequest,
    ) -> Result<Vec<u8>, String> {
        let Some(evidence) = verify_report_request.evidence else {
            return Err("Request does not have `evidence` proto.".to_string());
        };
        self.validate_signature(&evidence, verify_report_request.signature.as_slice())?;
        let endorsement = create_endorsements(verify_report_request.tee_certificate);
        let _ = oak_attestation_verification::verifier::verify(
            self.time_milis,
            &evidence,
            &endorsement,
            &self.appraisal_policy,
        )
        .map_err(|msg| format!("Failed to verify report. {}", msg))?;
        match self
            .crypter
            .as_mut()
            .unwrap()
            .encrypt(self.secret.as_bytes())
        {
            Ok(cipher_text) => Ok(cipher_text),
            Err(_) => Err("Failed to encrypt message.".to_string()),
        }
    }

    fn do_verify_report(&mut self, report: &[u8]) -> Result<Vec<u8>, String> {
        let Some(crypter) = &mut self.crypter else {
            return Err(
                "A successful handshake is require prior to process any request.".to_string(),
            );
        };
        let clear_text = crypter
            .decrypt(report)
            .map_err(|_| "Failed to decrypt request.")?;
        let verify_report_request = VerifyReportRequest::decode(clear_text.as_slice())
            .map_err(|_| "Failed to decode (serialize) request proto")?;
        self.check_report_and_encrypt_secret(verify_report_request)
    }

    fn validate_signature(&self, evidence: &Evidence, signature: &[u8]) -> Result<(), String> {
        // oak_attestation_verification::verifier::extract_evidence::verify() returns
        // the same proto that includes the parsed application keys; however, we want
        // to verify signatures before we validate the certificate (to early reject invalid requests).
        // Extracting application keys require some processing as they are represented as a CBOR
        // certificate, which contains claims and other values.
        let extracted_evidence = oak_attestation_verification::verifier::extract_evidence(evidence)
            .map_err(|msg| format!("Failed to extract evidence {}", msg))?;
        let signature = Signature::from_slice(signature)
            .map_err(|msg| format!("Failed to parse signature. {}", msg))?;
        let verifying_key =
            VerifyingKey::from_sec1_bytes(extracted_evidence.signing_public_key.as_slice())
                .map_err(|msg| {
                    format!(
                        "Failed to de-serialize application signing key from evidence. {}",
                        msg
                    )
                })?;
        verifying_key
            .verify(&self.handshake_hash, &signature)
            .map_err(|msg| format!("Signature does not match. {}", msg))
    }

    // Drop crypter and handshake hash to force clients to re-initiate the session.
    fn terminate(&mut self) {
        self.crypter = None;
        self.handshake_hash = [0; SHA256_OUTPUT_LEN];
        self.terminated = true;
    }

    fn is_terminated(&self) -> bool {
        self.terminated
    }
}

fn create_endorsements(
    tee_certificate: Vec<u8>,
) -> oak_proto_rust::oak::attestation::v1::Endorsements {
    let root_layer = oak_proto_rust::oak::attestation::v1::RootLayerEndorsements {
        tee_certificate: tee_certificate,
        stage0: None,
    };
    let ends = oak_proto_rust::oak::attestation::v1::OakContainersEndorsements {
        root_layer: Some(root_layer),
        container_layer: None,
        kernel_layer: None,
        system_layer: None,
    };
    oak_proto_rust::oak::attestation::v1::Endorsements {
        r#type: Some(oak_proto_rust::oak::attestation::v1::endorsements::Type::OakContainers(ends)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::privacy_sandbox::tvs::{InitSessionRequest, VerifyReportRequestEncrypted};
    use crypto::P256Scalar;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    fn get_good_evidence() -> oak_proto_rust::oak::attestation::v1::Evidence {
        oak_proto_rust::oak::attestation::v1::Evidence::decode(
            include_bytes!("../../test_data/good_evidence.binarypb").as_slice(),
        )
        .expect("could not decode evidence")
    }

    fn get_bad_evidence() -> oak_proto_rust::oak::attestation::v1::Evidence {
        oak_proto_rust::oak::attestation::v1::Evidence::decode(
            include_bytes!("../../test_data/bad_evidence.binarypb").as_slice(),
        )
        .expect("could not decode evidence")
    }

    fn get_malformed_evidence() -> oak_proto_rust::oak::attestation::v1::Evidence {
        oak_proto_rust::oak::attestation::v1::Evidence::decode(
            include_bytes!("../../test_data/malformed_evidence.binarypb").as_slice(),
        )
        .expect("could not decode evidence")
    }

    fn get_genoa_vcek() -> Vec<u8> {
        include_bytes!("../../test_data/vcek_genoa.crt").to_vec()
    }

    fn default_appraisal_policy() -> Vec<u8> {
        include_bytes!("../../test_data/on-perm-reference.binarypb").to_vec()
    }

    fn hash_and_sign(handshake_hash: &[u8], signing_key: &[u8]) -> Result<Vec<u8>, String> {
        let signing_key = SigningKey::from_slice(signing_key)
            .map_err(|msg| format!("Failed to parse signing keys. {}", msg))?;
        let signature: Signature = signing_key.sign(handshake_hash);
        Ok(signature.to_vec())
    }

    fn handshake_to_attest_report_request(handshake: Vec<u8>) -> Result<Vec<u8>, String> {
        // Test initial handshake.
        let message = AttestReportRequest {
            request: Some(
                proto::privacy_sandbox::tvs::attest_report_request::Request::InitSessionRequest(
                    InitSessionRequest {
                        client_message: handshake,
                    },
                ),
            ),
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
        let tvs_private_key = P256Scalar::generate();
        const SECRET: &str = "some_secret1";
        let mut trusted_tvs = new_trusted_tvs_service(
            NOW_UTC_MILLIS,
            &hex::encode(tvs_private_key.bytes()),
            default_appraisal_policy().as_slice(),
            SECRET,
        )
        .unwrap();
        let mut client =
            handshake::test_client::HandshakeInitiator::new(&tvs_private_key.compute_public_key());

        // Ask TVS to do its handshake part
        let handshake_bin = trusted_tvs
            .verify_report(
                handshake_to_attest_report_request(client.build_initial_message())
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

        let (handshake_hash, mut client_crypter) =
            client.process_response(handshake_response.as_slice());

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
            request: Some(
                proto::privacy_sandbox::tvs::attest_report_request::Request::VerifyReportRequest(
                    VerifyReportRequestEncrypted {
                        client_message: encrypted_report,
                    },
                ),
            ),
        };

        let mut message_bin: Vec<u8> = Vec::with_capacity(256);
        message.encode(&mut message_bin).unwrap();

        // Get the report.
        let secret_bin = trusted_tvs.verify_report(message_bin.as_slice()).unwrap();
        let message_reponse: AttestReportResponse =
            AttestReportResponse::decode(secret_bin.as_slice()).unwrap();

        let report_response = match &message_reponse.response {
            Some(attest_report_response::Response::VerifyReportResponse(report_response)) => {
                report_response.response_for_client.clone()
            }
            _ => panic!("Wrong response"),
        };

        let secret = client_crypter.decrypt(report_response.as_slice()).unwrap();
        let secret_text = std::str::from_utf8(secret.as_slice()).unwrap();
        assert_eq!(secret_text, SECRET);
    }

    // Test that the handshake session is terminated after the first
    // VerifyReportRequest regardless of the success status.
    #[test]
    fn verify_report_session_termination_on_successful_session() {
        let tvs_private_key = P256Scalar::generate();
        const SECRET: &str = "some_secret2";
        let mut trusted_tvs = new_trusted_tvs_service(
            NOW_UTC_MILLIS,
            &hex::encode(tvs_private_key.bytes()),
            default_appraisal_policy().as_slice(),
            SECRET,
        )
        .unwrap();
        let mut client =
            handshake::test_client::HandshakeInitiator::new(&tvs_private_key.compute_public_key());

        // Ask TVS to do its handshake part
        let handshake_bin = trusted_tvs
            .verify_report(
                handshake_to_attest_report_request(client.build_initial_message())
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

        let (handshake_hash, mut client_crypter) =
            client.process_response(handshake_response.as_slice());

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
            request: Some(
                proto::privacy_sandbox::tvs::attest_report_request::Request::VerifyReportRequest(
                    VerifyReportRequestEncrypted {
                        client_message: encrypted_report,
                    },
                ),
            ),
        };

        let mut message_bin: Vec<u8> = Vec::with_capacity(256);
        message.encode(&mut message_bin).unwrap();

        // Get the report.
        let secret_bin = trusted_tvs.verify_report(message_bin.as_slice()).unwrap();
        let message_reponse: AttestReportResponse =
            AttestReportResponse::decode(secret_bin.as_slice()).unwrap();

        let report_response = match &message_reponse.response {
            Some(attest_report_response::Response::VerifyReportResponse(report_response)) => {
                report_response.response_for_client.clone()
            }
            _ => panic!("Wrong response"),
        };

        let secret = client_crypter.decrypt(report_response.as_slice()).unwrap();
        let secret_text = std::str::from_utf8(secret.as_slice()).unwrap();
        assert_eq!(secret_text, SECRET);

        match trusted_tvs.verify_report(message_bin.as_slice()) {
            Ok(_) => assert!(false, "verify_command() should fail."),
            Err(e) => assert!(e.contains("The session is terminated.")),
        }

        match trusted_tvs.verify_report(
            handshake_to_attest_report_request(client.build_initial_message())
                .unwrap()
                .as_slice(),
        ) {
            Ok(_) => assert!(false, "verify_command() should fail."),
            Err(e) => assert!(e.contains("The session is terminated.")),
        }
    }

    #[test]
    fn verify_report_invalid_report_error() {
        let tvs_private_key = P256Scalar::generate();
        let mut trusted_tvs = new_trusted_tvs_service(
            NOW_UTC_MILLIS,
            &hex::encode(tvs_private_key.bytes()),
            default_appraisal_policy().as_slice(),
            "secret",
        )
        .unwrap();
        let mut client =
            handshake::test_client::HandshakeInitiator::new(&tvs_private_key.compute_public_key());

        // Ask TVS to do its handshake part
        let handshake_bin = trusted_tvs
            .verify_report(
                handshake_to_attest_report_request(client.build_initial_message())
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

        let (handshake_hash, mut client_crypter) =
            client.process_response(handshake_response.as_slice());
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
            request: Some(
                proto::privacy_sandbox::tvs::attest_report_request::Request::VerifyReportRequest(
                    VerifyReportRequestEncrypted {
                        client_message: encrypted_report,
                    },
                ),
            ),
        };

        let mut message_bin: Vec<u8> = Vec::with_capacity(256);
        message.encode(&mut message_bin).unwrap();
        let mut message_bin: Vec<u8> = Vec::with_capacity(256);
        message.encode(&mut message_bin).unwrap();

        match trusted_tvs.verify_report(message_bin.as_slice()) {
            Ok(_) => assert!(false, "verify_command() should fail."),
            Err(e) => assert!(e.contains("Failed to verify report. chip id differs")),
        }

        match trusted_tvs.verify_report(message_bin.as_slice()) {
            Ok(_) => assert!(false, "verify_command() should fail."),
            Err(e) => assert!(e.contains("The session is terminated.")),
        }
    }

    #[test]
    fn verify_report_system_layer_verification_error() {
        let tvs_private_key = P256Scalar::generate();
        let mut trusted_tvs = new_trusted_tvs_service(
            NOW_UTC_MILLIS,
            &hex::encode(tvs_private_key.bytes()),
            default_appraisal_policy().as_slice(),
            "secret",
        )
        .unwrap();
        let mut client =
            handshake::test_client::HandshakeInitiator::new(&tvs_private_key.compute_public_key());

        // Ask TVS to do its handshake part
        let handshake_bin = trusted_tvs
            .verify_report(
                handshake_to_attest_report_request(client.build_initial_message())
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

        let (handshake_hash, mut client_crypter) =
            client.process_response(handshake_response.as_slice());
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
            request: Some(
                proto::privacy_sandbox::tvs::attest_report_request::Request::VerifyReportRequest(
                    VerifyReportRequestEncrypted {
                        client_message: encrypted_report,
                    },
                ),
            ),
        };

        let mut message_bin: Vec<u8> = Vec::with_capacity(256);
        message.encode(&mut message_bin).unwrap();

        match trusted_tvs.verify_report(message_bin.as_slice()) {
            Ok(_) => assert!(false, "verify_command() should fail."),
            Err(e) => {
                assert!(e.contains("Failed to verify report. system layer verification failed"))
            }
        }
    }

    #[test]
    fn new_trusted_tvs_service_error() {
        match new_trusted_tvs_service(
            NOW_UTC_MILLIS,
            &format!("{}fg", ["ff"; 31].join("")),
            default_appraisal_policy().as_slice(),
            "test_secret",
        ) {
            Ok(_) => assert!(false, "new_trusted_tvs_service() should fail."),
            Err(e) => assert_eq!(
                e,
                "Invalid private key format. Private key should be formatted as hex string."
            ),
        }

        match new_trusted_tvs_service(
            NOW_UTC_MILLIS,
            "abcd",
            default_appraisal_policy().as_slice(),
            "test_secret",
        ) {
            Ok(_) => assert!(false, "new_trusted_tvs_service() should fail."),
            Err(e) => assert_eq!(
                e,
                format!(
                    "Invalid private key length. Key should be {} bytes long.",
                    P256_SCALAR_LENGTH
                )
            ),
        }

        match new_trusted_tvs_service(
            NOW_UTC_MILLIS,
            &String::from_utf8(vec![b'f'; P256_SCALAR_LENGTH * 3]).unwrap(),
            default_appraisal_policy().as_slice(),
            "test_secret",
        ) {
            Ok(_) => assert!(false, "new_trusted_tvs_service() should fail."),
            Err(e) => assert_eq!(
                e,
                format!(
                    "Invalid private key length. Key should be {} bytes long.",
                    P256_SCALAR_LENGTH
                )
            ),
        }

        let tvs_private_key = P256Scalar::generate();
        match new_trusted_tvs_service(
            NOW_UTC_MILLIS,
            &hex::encode(tvs_private_key.bytes()),
            &[1, 2, 3],
            "test_secret",
        ) {
            Ok(_) => assert!(false, "new_trusted_tvs_service() should fail."),
            Err(e) => assert_eq!(e, "Failed to decode (serialize) appraisal policy.",),
        }
    }

    #[test]
    fn handshake_error() {
        let tvs_private_key = P256Scalar::generate();
        let mut trusted_tvs = new_trusted_tvs_service(
            NOW_UTC_MILLIS,
            &hex::encode(tvs_private_key.bytes()),
            default_appraisal_policy().as_slice(),
            "test_secret",
        )
        .unwrap();

        // Test invalid initiator handshake error.
        match trusted_tvs.do_init_session(b"ab") {
            Ok(_) => assert!(false, "do_init_session() should fail."),
            Err(e) => assert_eq!(e, "Handshake has already been made.".to_string()),
        }

        let mut trusted_tvs = new_trusted_tvs_service(
            NOW_UTC_MILLIS,
            &hex::encode(tvs_private_key.bytes()),
            default_appraisal_policy().as_slice(),
            "test_secret",
        )
        .unwrap();
        let client_handshake =
            handshake::test_client::HandshakeInitiator::new(&tvs_private_key.compute_public_key())
                .build_initial_message();
        assert!(trusted_tvs
            .do_init_session(client_handshake.as_slice())
            .is_ok());
        // Test duplicate initiator handshake error.
        match trusted_tvs.do_init_session(client_handshake.as_slice()) {
            Ok(_) => assert!(false, "do_init_session() should fail."),
            Err(e) => assert_eq!(e, "Handshake has already been made.".to_string()),
        }
    }

    #[test]
    fn verify_report_error() {
        let tvs_private_key = P256Scalar::generate();
        let mut trusted_tvs = new_trusted_tvs_service(
            NOW_UTC_MILLIS,
            &hex::encode(tvs_private_key.bytes()),
            default_appraisal_policy().as_slice(),
            "secret",
        )
        .unwrap();
        match trusted_tvs.do_verify_report(b"aaa") {
            Ok(_) => assert!(false, "do_verify_command() should fail."),
            Err(e) => assert_eq!(
                e,
                "A successful handshake is require prior to process any request.".to_string()
            ),
        }
    }
}
