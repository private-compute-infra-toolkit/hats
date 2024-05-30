#![no_main] // main defined in C++ by main.cc

extern crate hex;
use crate::proto::privacy_sandbox::tvs::{
    attest_report_request, attest_report_response, AttestReportRequest, AttestReportResponse,
    InitSessionRequest, VerifyReportRequestEncrypted,
};

use oak_crypto::noise_handshake::client::HandshakeInitiator;
use oak_crypto::noise_handshake::{Crypter, P256_X962_LEN};

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
        fn build_command(&mut self, message: &str) -> Result<Vec<u8>>;
        fn process_response(&mut self, response: &[u8]) -> Result<String>;
    }
}

fn new_tvs_client(tvs_pub_key: &str) -> Result<Box<TvsClient>, String> {
    let tvs_pub_key = hex::decode(tvs_pub_key)
        .map_err(|_| "Cannot decode tvs_pub_key. The key is expected to be in hex format")?;
    let tvs_pub_key_bytes: [u8; P256_X962_LEN] = tvs_pub_key
        .try_into()
        .map_err(|_| format!("Expected tvs_pub_key to be of length {}.", P256_X962_LEN))?;
    Ok(Box::new(TvsClient::new(&tvs_pub_key_bytes)))
}

struct TvsClient {
    handshake: HandshakeInitiator,
    crypter: Option<Crypter>,
}

impl TvsClient {
    fn new(peer_public_key: &[u8; P256_X962_LEN]) -> Self {
        Self {
            handshake: HandshakeInitiator::new_nk(peer_public_key),
            crypter: None,
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
        let (_, crypter) = self
            .handshake
            .process_response(handshake_response.as_slice());
        self.crypter = Some(crypter);
        Ok(())
    }

    fn build_command(&mut self, message: &str) -> Result<Vec<u8>, String> {
        if let Some(crypter) = self.crypter.as_mut() {
            match crypter.encrypt(message.as_bytes()) {
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
