#![no_main] // main defined in C++ by main.cc

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

#[cxx::bridge(namespace = "privacy_sandbox::tvs::test_client")]
mod ffi {
    extern "Rust" {
        type TvsClient;
        fn new_tvs_client(tvs_pub_key: &str) -> Result<Box<TvsClient>>;
        fn build_initial_message(&mut self) -> Result<Vec<u8>>;
        fn process_handshake_response(&mut self, response: &[u8]) -> Result<()>;
        fn build_command(&mut self, message: &[u8]) -> Result<Vec<u8>>;
        fn build_verify_report_request(
            &mut self,
            evidence_bin: &[u8],
            vcek: &[u8],
            application_signing_key: &str,
        ) -> Result<Vec<u8>>;
        fn process_response(&mut self, response: &[u8]) -> Result<String>;
    }
}

fn new_tvs_client(tvs_pub_key: &str) -> Result<Box<TvsClient>, String> {
    let tvs_pub_key = hex::decode(tvs_pub_key)
        .map_err(|_| "Cannot decode tvs_pub_key. The key is expected to be in hex format")?;
    let tvs_pub_key_bytes: [u8; P256_X962_LENGTH] = tvs_pub_key
        .try_into()
        .map_err(|_| format!("Expected tvs_pub_key to be of length {}.", P256_X962_LENGTH))?;
    Ok(Box::new(TvsClient::new(tvs_pub_key_bytes)))
}

struct TvsClient {
    handshake: HandshakeInitiator,
    crypter: Option<Crypter>,
    handshake_hash: [u8; SHA256_OUTPUT_LEN],
}

impl TvsClient {
    fn new(peer_public_key: [u8; P256_X962_LENGTH]) -> Self {
        Self {
            handshake: HandshakeInitiator::new(&peer_public_key),
            crypter: None,
            handshake_hash: [0; SHA256_OUTPUT_LEN],
        }
    }

    fn build_initial_message(&mut self) -> Result<Vec<u8>, String> {
        let mut message_bin: Vec<u8> = Vec::with_capacity(256);
        AttestReportRequest {
            request: Some(attest_report_request::Request::InitSessionRequest(
                InitSessionRequest {
                    client_message: self.handshake.build_initial_message(),
                },
            )),
        }
        .encode(&mut message_bin)
        .map_err(|_| "Error encoding handshake initial message to AttestReportRequest proto")?;
        Ok(message_bin)
    }

    fn process_handshake_response(&mut self, response: &[u8]) -> Result<(), String> {
        let message_reponse: AttestReportResponse = prost::Message::decode(response)
            .map_err(|_| "process_handshake_response() failed. Error decoding message to AttestReportResponse proto.".to_string())?;
        let handshake_response = match &message_reponse.response {
            Some(attest_report_response::Response::InitSessionResponse(init_session)) => {
                init_session.response_for_client.clone()
            }
            _ => {
                return Err("Unexpected proto message".to_string());
            }
        };
        let (handshake_hash, crypter) = self
            .handshake
            .process_response(handshake_response.as_slice());
        self.crypter = Some(crypter);
        self.handshake_hash = handshake_hash;
        Ok(())
    }

    fn build_command(&mut self, message: &[u8]) -> Result<Vec<u8>, String> {
        if let Some(crypter) = self.crypter.as_mut() {
            match crypter.encrypt(message) {
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

    fn build_verify_report_request(
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
            .map_err(|_| "process_handshake_response() failed. Error decoding message to AttestReportResponse proto.".to_string())?;
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

    fn process_response(&mut self, response: &[u8]) -> Result<String, String> {
        let Some(crypter) = self.crypter.as_mut() else {
            return Err(
                "Handshake initiation should be done before encrypting messages".to_string(),
            );
        };
        let response: AttestReportResponse = prost::Message::decode(response).map_err(|_| {
            "process_response failed. Error decoding message to AttestReportResponse proto."
                .to_string()
        })?;
        let report_response = match &response.response {
            Some(attest_report_response::Response::VerifyReportResponse(report_response)) => {
                report_response.response_for_client.clone()
            }
            _ => return Err("Unexpected proto message".to_string()),
        };
        match crypter.decrypt(report_response.as_slice()) {
            Ok(plain_text) => match std::str::from_utf8(plain_text.as_slice()) {
                Ok(token) => Ok(token.to_string()),
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
