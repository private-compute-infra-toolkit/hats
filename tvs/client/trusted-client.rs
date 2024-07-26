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

extern crate hex;
use crate::proto::privacy_sandbox::tvs::{
    attest_report_request, attest_report_response, AttestReportRequest, AttestReportResponse,
    InitSessionRequest, VerifyReportRequest, VerifyReportRequestEncrypted,
};

use crypto::{P256_X962_LENGTH, SHA256_OUTPUT_LEN};
use handshake::{test_client::HandshakeInitiator, Crypter};
use oak_proto_rust::oak::attestation::v1::Evidence;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};

use prost::Message;

pub mod proto {
    pub mod privacy_sandbox {
        pub mod tvs {
            include!(concat!(env!("OUT_DIR"), "/privacy_sandbox.tvs.rs"));
        }
    }
}

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
        fn new_tvs_client(tvs_pub_key: &str) -> Result<Box<TvsClient>>;
        fn build_initial_message(&mut self) -> Result<Vec<u8>>;
        fn process_handshake_response(&mut self, response: &[u8]) -> Result<()>;
        fn build_verify_report_request(
            &mut self,
            evidence_bin: &[u8],
            vcek: &[u8],
            application_signing_key: &str,
        ) -> Result<Vec<u8>>;
        fn process_response(&mut self, response: &[u8]) -> Result<String>;
    }
}

pub fn new_tvs_client(tvs_pub_key: &str) -> Result<Box<TvsClient>, String> {
    let tvs_pub_key = hex::decode(tvs_pub_key)
        .map_err(|_| "Cannot decode tvs_pub_key. The key is expected to be in hex format")?;
    let tvs_pub_key_bytes: [u8; P256_X962_LENGTH] = tvs_pub_key
        .try_into()
        .map_err(|_| format!("Expected tvs_pub_key to be of length {}.", P256_X962_LENGTH))?;
    Ok(Box::new(TvsClient::new(tvs_pub_key_bytes)))
}

pub struct TvsClient {
    handshake: HandshakeInitiator,
    crypter: Option<Crypter>,
    handshake_hash: [u8; SHA256_OUTPUT_LEN],
    peer_public_key: [u8; P256_X962_LENGTH],
}

impl TvsClient {
    fn new(peer_public_key: [u8; P256_X962_LENGTH]) -> Self {
        Self {
            handshake: HandshakeInitiator::new(&peer_public_key),
            crypter: None,
            handshake_hash: [0; SHA256_OUTPUT_LEN],
            peer_public_key,
        }
    }

    pub fn build_initial_message(&mut self) -> Result<Vec<u8>, String> {
        let mut message_bin: Vec<u8> = Vec::with_capacity(256);
        AttestReportRequest {
            request: Some(attest_report_request::Request::InitSessionRequest(
                InitSessionRequest {
                    client_message: self.handshake.build_initial_message(),
                    tvs_public_key: self.peer_public_key.to_vec(),
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
            .process_response(handshake_response.as_slice());
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
                signature: signature,
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

    pub fn process_response(&mut self, response: &[u8]) -> Result<String, String> {
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
            Ok(plain_text) => match std::str::from_utf8(plain_text.as_slice()) {
                Ok(secret) => Ok(secret.to_string()),
                Err(_) => Err("Failed to convert decrypted message to utf8 string".to_string()),
            },
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

    fn get_genoa_vcek() -> Vec<u8> {
        include_bytes!("../test_data/vcek_genoa.crt").to_vec()
    }

    fn default_appraisal_policy() -> Vec<u8> {
        include_bytes!("../test_data/on-perm-reference.binarypb").to_vec()
    }

    fn get_good_evidence() -> Vec<u8> {
        include_bytes!("../test_data/good_evidence.binarypb").to_vec()
    }

    const NOW_UTC_MILLIS: i64 = 1698829200000;

    // End to end testing: handshake, building and signing the report and decrypt the secret.
    #[test]
    fn verify_report_successful() {
        let tvs_private_key = P256Scalar::generate();
        const SECRET: &str = "some_secret2";
        let mut trusted_tvs_service = tvs_trusted::new_trusted_tvs_service(
            NOW_UTC_MILLIS,
            &tvs_private_key.bytes(),
            default_appraisal_policy().as_slice(),
            SECRET,
        )
        .unwrap();

        let mut tvs_client =
            new_tvs_client(&hex::encode(tvs_private_key.compute_public_key())).unwrap();
        let initial_message = tvs_client.build_initial_message().unwrap();

        let handshake_response = trusted_tvs_service
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
        let secret = trusted_tvs_service
            .verify_report(report.as_slice())
            .unwrap();

        let decrypted_secret = tvs_client.process_response(secret.as_slice()).unwrap();
        assert_eq!(decrypted_secret, SECRET);
    }

    #[test]
    fn process_handshake_response_error() {
        let tvs_private_key = P256Scalar::generate();
        let mut tvs_client =
            new_tvs_client(&hex::encode(tvs_private_key.compute_public_key())).unwrap();
        match tvs_client.process_handshake_response(&[1, 2, 3]) {
            Ok(_) => assert!(false, "process_handshake_response() should fail"),
            Err(e) => assert_eq!(e, "Error decoding message to AttestReportResponse proto."),
        }
        let report = AttestReportRequest {
            request: Some(
                proto::privacy_sandbox::tvs::attest_report_request::Request::VerifyReportRequest(
                    VerifyReportRequestEncrypted {
                        client_message: vec![1, 2],
                    },
                ),
            ),
        };
        let mut report_bin: Vec<u8> = Vec::with_capacity(256);
        report.encode(&mut report_bin).unwrap();
        match tvs_client.process_handshake_response(report_bin.as_slice()) {
            Ok(_) => assert!(false, "process_handshake_response() should fail"),
            Err(e) => assert_eq!(e, "Unexpected proto message."),
        }
    }

    #[test]
    fn process_response_error() {
        let tvs_private_key = P256Scalar::generate();
        let mut tvs_client =
            new_tvs_client(&hex::encode(tvs_private_key.compute_public_key())).unwrap();
        match tvs_client.process_response(&[1, 2, 3]) {
            Ok(_) => assert!(false, "process_response() should fail"),
            Err(e) => assert_eq!(
                e,
                "Handshake initiation should be done before encrypting messages."
            ),
        }

        let mut trusted_tvs_service = tvs_trusted::new_trusted_tvs_service(
            NOW_UTC_MILLIS,
            &tvs_private_key.bytes(),
            default_appraisal_policy().as_slice(),
            "test_secret",
        )
        .unwrap();

        // Perform handshake now so we get to the next error.
        let initial_message = tvs_client.build_initial_message().unwrap();

        let handshake_response = trusted_tvs_service
            .verify_report(initial_message.as_slice())
            .unwrap();
        tvs_client
            .process_handshake_response(&handshake_response)
            .unwrap();

        match tvs_client.process_response(&[1, 2, 3]) {
            Ok(_) => assert!(false, "process_response() should fail"),
            Err(e) => assert_eq!(e, "Error decoding message to AttestReportResponse proto."),
        }
        let report = AttestReportRequest {
            request: Some(
                proto::privacy_sandbox::tvs::attest_report_request::Request::VerifyReportRequest(
                    VerifyReportRequestEncrypted {
                        client_message: vec![1, 2],
                    },
                ),
            ),
        };
        let mut report_bin: Vec<u8> = Vec::with_capacity(256);
        report.encode(&mut report_bin).unwrap();
        match tvs_client.process_response(report_bin.as_slice()) {
            Ok(_) => assert!(false, "process_response() should fail"),
            Err(e) => assert_eq!(e, "Failed to decrypt ciphertext."),
        }
    }

    #[test]
    fn new_tvs_client_error() {
        match new_tvs_client("--") {
            Ok(_) => assert!(false, "new_tvs_client() should fail"),
            Err(e) => assert_eq!(
                e,
                "Cannot decode tvs_pub_key. The key is expected to be in hex format"
            ),
        }
        match new_tvs_client("ffff") {
            Ok(_) => assert!(false, "new_tvs_client() should fail"),
            Err(e) => assert_eq!(
                e,
                format!("Expected tvs_pub_key to be of length {}.", P256_X962_LENGTH)
            ),
        }
    }
}
