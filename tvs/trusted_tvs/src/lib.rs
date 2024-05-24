// Required for prost
#![feature(never_type)]

extern crate hex;
extern crate oak_crypto;

use crate::proto::privacy_sandbox::tvs::{
    attest_report_request, attest_report_response, AttestReportRequest, AttestReportResponse,
    InitSessionResponse, VerifyReportResponseEncrypted,
};
use jwt_simple::prelude::*;
use oak_crypto::noise_handshake;
use prost::Message;
use std::fmt;

const P256_SCALAR_LEN: usize = 32;

pub mod proto {
    pub mod privacy_sandbox {
        pub mod tvs {
            use prost::Message;
            include!(concat!(env!("OUT_DIR"), "/privacy_sandbox.tvs.rs"));
        }
    }
}

#[derive(PartialEq, Debug)]
enum TrustedTvsError {
    InvalidPrivateKeyFormat,
    InvalidPrivateKeyLength,
    DuplicateHandshake,
    FailedHandshake,
    FailedDecryption,
    FailedEncryption,
    FailedPrecondition,
    UnknownCommand,
}

impl fmt::Display for TrustedTvsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustedTvsError::InvalidPrivateKeyFormat => write!(
                f,
                "Invalid private key format. Private key should be formatted as hex string."
            ),
            TrustedTvsError::InvalidPrivateKeyLength => write!(
                f,
                "Invalid private key length. Key should be {} bytes long.",
                P256_SCALAR_LEN
            ),
            TrustedTvsError::FailedHandshake => {
                write!(f, "Failed to process initiator's handshake.")
            }
            TrustedTvsError::DuplicateHandshake => write!(f, "Handshake has already been made."),
            TrustedTvsError::FailedDecryption => write!(f, "Failed to decrypt a message."),
            TrustedTvsError::FailedEncryption => write!(f, "Failed to encrypt a message."),
            TrustedTvsError::FailedPrecondition => write!(
                f,
                "Failed precondition: crypto cannot start before a successful handshake."
            ),
            TrustedTvsError::UnknownCommand => write!(f, "Received an unknown command."),
        }
    }
}

struct TrustedTvs {
    // A big-endian P-256 private scalar, used as the Noise identity key.
    identity_private_key: [u8; P256_SCALAR_LEN],
    crypter: Option<noise_handshake::Crypter>,
    // TODO(alwabel): remove the handshake hash.
    handshake_hash: [u8; 32],
}

// Export TrustedTvs and it's methods to C++.
// The implementation is exported to under `privacy_sandbox::tee_verification` namespace.
// Example usage in c++:
//     rust::Box<privacy_sandbox::tee_verification::TrustedTvs> tvs =
//        privacy_sandbox::tee_verification::new_trusted_tvs_service(key);
//        rust::Vec<std::uint8_t> result = trusted_tvs->verify_report(...);
#[cxx::bridge(namespace = "privacy_sandbox::tee_verification")]
mod ffi {
    extern "Rust" {
        type TrustedTvs;
        fn new_trusted_tvs_service(private_key_in_hex_str: &str) -> Result<Box<TrustedTvs>>;
        pub fn verify_report(self: &mut TrustedTvs, request: &[u8]) -> Result<Vec<u8>>;
    }
}

fn new_trusted_tvs_service(
    private_key_in_hex_str: &str,
) -> Result<Box<TrustedTvs>, TrustedTvsError> {
    match hex::decode(private_key_in_hex_str) {
        Ok(identity_private_key) => {
            let identity_private_key_fixed_size: [u8; P256_SCALAR_LEN] = identity_private_key
                .try_into()
                .map_err(|_| TrustedTvsError::InvalidPrivateKeyLength)?;
            Ok(Box::new(TrustedTvs::new(&identity_private_key_fixed_size)))
        }
        Err(_) => Err(TrustedTvsError::InvalidPrivateKeyFormat),
    }
}

impl TrustedTvs {
    fn new(identity_private_key: &[u8; P256_SCALAR_LEN]) -> Self {
        Self {
            identity_private_key: *identity_private_key,
            crypter: None,
            handshake_hash: [0; 32],
        }
    }

    pub fn verify_report(
        self: &mut TrustedTvs,
        request: &[u8],
    ) -> Result<Vec<u8>, TrustedTvsError> {
        let request: AttestReportRequest =
            prost::Message::decode(request).map_err(|_| TrustedTvsError::UnknownCommand)?;
        let response = self.attest_report_internal(&request)?;
        let mut buf: Vec<u8> = Vec::with_capacity(1024);
        response
            .encode(&mut buf)
            .map_err(|_| TrustedTvsError::UnknownCommand)?;
        Ok(buf)
    }

    pub fn attest_report_internal(
        &mut self,
        request: &AttestReportRequest,
    ) -> Result<AttestReportResponse, TrustedTvsError> {
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
                let token = self.do_verify_report(verify_report.client_message.as_slice())?;
                Ok(AttestReportResponse {
                    response: Some(attest_report_response::Response::VerifyReportResponse(
                        VerifyReportResponseEncrypted {
                            response_for_client: token,
                        },
                    )),
                })
            }
            None => Err(TrustedTvsError::FailedPrecondition),
        }
    }

    fn do_init_session(&mut self, handshake_request: &[u8]) -> Result<Vec<u8>, TrustedTvsError> {
        if let Some(_) = &self.crypter {
            Err(TrustedTvsError::DuplicateHandshake)
        } else {
            match noise_handshake::respond_nk(&self.identity_private_key, handshake_request) {
                Ok(r) => {
                    self.crypter = Some(r.crypter);
                    self.handshake_hash = r.handshake_hash;
                    Ok(r.response)
                }
                Err(_) => Err(TrustedTvsError::FailedHandshake),
            }
        }
    }

    fn check_report_and_generate_token(
        &mut self,
        command: String,
    ) -> Result<Vec<u8>, TrustedTvsError> {
        // TODO(alwabel): Validate and verify the attestation report. Right now we
        // just look for `verify` keyword.
        match &command[..] {
            "verify" => {
                match self
                    .crypter
                    .as_mut()
                    .unwrap()
                    .encrypt(issue_jwt_token().as_bytes())
                {
                    Ok(cipher_text) => Ok(cipher_text),
                    Err(_) => Err(TrustedTvsError::FailedEncryption),
                }
            }
            _ => Err(TrustedTvsError::UnknownCommand),
        }
    }

    fn do_verify_report(&mut self, report: &[u8]) -> Result<Vec<u8>, TrustedTvsError> {
        let Some(crypter) = &mut self.crypter else {
            return Err(TrustedTvsError::FailedPrecondition);
        };
        match crypter.decrypt(report) {
            Ok(clear_text) => match String::from_utf8(clear_text) {
                Ok(command) => self.check_report_and_generate_token(command),
                Err(_) => Err(TrustedTvsError::UnknownCommand),
            },
            Err(_) => Err(TrustedTvsError::FailedDecryption),
        }
    }
}

// TODO(alwabel): fill in the token with actual data and properly sing it.
// Generates a simple JWT token -- see https://jwt.io/
fn issue_jwt_token() -> String {
    let key = HS384Key::from_bytes(b"secret");
    let claims = Claims::create(Duration::from_secs(5));
    let token = key.authenticate(claims).unwrap();
    token
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::privacy_sandbox::tvs::{InitSessionRequest, VerifyReportRequestEncrypted};
    use oak_crypto::noise_handshake::client::HandshakeInitiator;
    use oak_crypto::noise_handshake::P256Scalar;

    #[test]
    fn verify_report_successful() {
        let tvs_private_key = P256Scalar::generate();
        let mut trusted_tvs =
            new_trusted_tvs_service(&hex::encode(tvs_private_key.bytes())).unwrap();
        let mut client = HandshakeInitiator::new_nk(&tvs_private_key.compute_public_key());

        // Test initial handshake.
        let message = AttestReportRequest {
            request: Some(
                proto::privacy_sandbox::tvs::attest_report_request::Request::InitSessionRequest(
                    InitSessionRequest {
                        client_message: client.build_initial_message(),
                    },
                ),
            ),
        };
        let mut message_bin: Vec<u8> = Vec::with_capacity(256);
        message.encode(&mut message_bin).unwrap();

        // Ask TVS to do its handshake part
        let handshake_bin = trusted_tvs.verify_report(message_bin.as_slice()).unwrap();

        let message_reponse: AttestReportResponse =
            prost::Message::decode(handshake_bin.as_slice()).unwrap();
        let handshake_response = match &message_reponse.response {
            Some(attest_report_response::Response::InitSessionResponse(init_session)) => {
                init_session.response_for_client.clone()
            }
            _ => panic!("Wrong response"),
        };

        let (_, mut client_crypter) = client.process_response(handshake_response.as_slice());

        let mut encrypted_tokens = Vec::with_capacity(256);

        for _ in 0..10 {
            // Test report verification.
            let encrypted_report = client_crypter.encrypt("verify".as_bytes()).unwrap();
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
            let token_bin = trusted_tvs.verify_report(message_bin.as_slice()).unwrap();
            let message_reponse: AttestReportResponse =
                prost::Message::decode(token_bin.as_slice()).unwrap();

            let report_response = match &message_reponse.response {
                Some(attest_report_response::Response::VerifyReportResponse(report_response)) => {
                    report_response.response_for_client.clone()
                }
                _ => panic!("Wrong response"),
            };

            encrypted_tokens.push(report_response.clone());
            let jwt_token = client_crypter.decrypt(report_response.as_slice()).unwrap();
            let jwt_token_text = std::str::from_utf8(jwt_token.as_slice()).unwrap();
            assert_eq!(jwt_token_text, issue_jwt_token());
        }
        encrypted_tokens.sort();
        // Sanity check: verify that the cipher text of the encrypted_tokens are unique.
        assert_eq!(
            1 + encrypted_tokens
                .windows(2)
                .filter(|element| element[0] != element[1])
                .count(),
            10
        );
    }

    #[test]
    fn new_trusted_tvs_service_error() {
        match new_trusted_tvs_service(&format!("{}fg", ["ff"; 31].join(""))) {
            Ok(_) => assert!(false, "new_trusted_tvs_service() should fail."),
            Err(e) => assert_eq!(e, TrustedTvsError::InvalidPrivateKeyFormat),
        }
        match new_trusted_tvs_service("abcd") {
            Ok(_) => assert!(false, "new_trusted_tvs_service() should fail."),
            Err(e) => assert_eq!(e, TrustedTvsError::InvalidPrivateKeyLength),
        }
        match new_trusted_tvs_service(&String::from_utf8(vec![b'f'; P256_SCALAR_LEN * 3]).unwrap())
        {
            Ok(_) => assert!(false, "new_trusted_tvs_service() should fail."),
            Err(e) => assert_eq!(e, TrustedTvsError::InvalidPrivateKeyLength),
        }
    }

    #[test]
    fn handshake_error() {
        let tvs_private_key = P256Scalar::generate();
        let mut trusted_tvs =
            new_trusted_tvs_service(&hex::encode(tvs_private_key.bytes())).unwrap();
        // Test invalid initiator handshake error.
        match trusted_tvs.do_init_session(b"ab") {
            Ok(_) => assert!(false, "do_init_session() should fail."),
            Err(e) => assert_eq!(e, TrustedTvsError::FailedHandshake),
        }

        let mut trusted_tvs =
            new_trusted_tvs_service(&hex::encode(tvs_private_key.bytes())).unwrap();
        let client_handshake = HandshakeInitiator::new_nk(&tvs_private_key.compute_public_key())
            .build_initial_message();
        assert!(trusted_tvs
            .do_init_session(client_handshake.as_slice())
            .is_ok());
        // Test duplicate initiator handshake error.
        match trusted_tvs.do_init_session(client_handshake.as_slice()) {
            Ok(_) => assert!(false, "do_init_session() should fail."),
            Err(e) => assert_eq!(e, TrustedTvsError::DuplicateHandshake),
        }
    }

    #[test]
    fn verify_report_error() {
        let tvs_private_key = P256Scalar::generate();
        let mut trusted_tvs =
            new_trusted_tvs_service(&hex::encode(tvs_private_key.bytes())).unwrap();
        match trusted_tvs.do_verify_report(b"aaa") {
            Ok(_) => assert!(false, "do_verify_command() should fail."),
            Err(e) => assert_eq!(e, TrustedTvsError::FailedPrecondition),
        }
    }
}
