// Required for prost
#![feature(never_type)]

extern crate handshake;
extern crate hex;

use crate::proto::privacy_sandbox::tvs::{
    attest_report_request, attest_report_response, AttestReportRequest, AttestReportResponse,
    InitSessionResponse, VerifyReportRequest, VerifyReportResponseEncrypted,
};
use crypto::P256_SCALAR_LENGTH;
use jwt_simple::prelude::*;
use prost::Message;

pub mod proto {
    pub mod privacy_sandbox {
        pub mod tvs {
            include!(concat!(env!("OUT_DIR"), "/privacy_sandbox.tvs.rs"));
        }
    }
}

struct TrustedTvs {
    time_milis: i64,
    // A big-endian P-256 private scalar, used as the Noise identity key.
    identity_private_key: [u8; P256_SCALAR_LENGTH],
    crypter: Option<handshake::Crypter>,
    appraisal_policy: oak_proto_rust::oak::attestation::v1::ReferenceValues,
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
        ) -> Result<Box<TrustedTvs>>;
        pub fn verify_report(self: &mut TrustedTvs, request: &[u8]) -> Result<Vec<u8>>;
    }
}

fn new_trusted_tvs_service(
    time_milis: i64,
    private_key_in_hex_str: &str,
    policy: &[u8],
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
    ) -> Self {
        Self {
            time_milis,
            identity_private_key: *identity_private_key,
            appraisal_policy,
            crypter: None,
        }
    }

    pub fn verify_report(self: &mut TrustedTvs, request: &[u8]) -> Result<Vec<u8>, String> {
        let request = AttestReportRequest::decode(request)
            .map_err(|_| "Failed to decode (serialize) AttestReportRequest.".to_string())?;
        let response = self.attest_report_internal(&request)?;
        let mut buf: Vec<u8> = Vec::with_capacity(1024);
        response.encode(&mut buf).map_err(|_| {
            "Failed to encode AttestReportRequest. Something must have gone wrong internally."
        })?;
        Ok(buf)
    }

    pub fn attest_report_internal(
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
                let token = self.do_verify_report(verify_report.client_message.as_slice())?;
                Ok(AttestReportResponse {
                    response: Some(attest_report_response::Response::VerifyReportResponse(
                        VerifyReportResponseEncrypted {
                            response_for_client: token,
                        },
                    )),
                })
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
                    Ok(r.response)
                }
                Err(_) => Err("Handshake has already been made.".to_string()),
            }
        }
    }

    fn check_report_and_generate_token(
        &mut self,
        verify_report_request: VerifyReportRequest,
    ) -> Result<Vec<u8>, String> {
        let endorsement = create_endorsements(verify_report_request.tee_certificate);
        let Some(evidence) = verify_report_request.evidence else {
            return Err("Request does not have `evidence` proto.".to_string());
        };
        // TODO(alwabel): verify against the right vcek cert chain as Oak
        // currently uses Milan's cert chains for all requests.
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
            .encrypt(issue_jwt_token().as_bytes())
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
        self.check_report_and_generate_token(verify_report_request)
    }
}

// TODO(alwabel): fill in the token with actual data and properly sign it.
// We need to  sign over the handshake hash and appraisal policy hash, proving
// we still have the signing private key, and that we agree on the appraisal
// policy.
// Generates a simple JWT token -- see https://jwt.io/
fn issue_jwt_token() -> String {
    let key = HS384Key::from_bytes(b"secret");
    let claims = Claims::create(Duration::from_secs(5));
    let token = key.authenticate(claims).unwrap();
    token
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

    fn get_oc_evidence() -> oak_proto_rust::oak::attestation::v1::Evidence {
        oak_proto_rust::oak::attestation::v1::Evidence::decode(
            include_bytes!("../../test_data/oc_evidence.binarypb").as_slice(),
        )
        .expect("could not decode evidence")
    }

    fn get_bad_evidence() -> oak_proto_rust::oak::attestation::v1::Evidence {
        oak_proto_rust::oak::attestation::v1::Evidence::decode(
            include_bytes!("../../test_data/bad_evidence.binarypb").as_slice(),
        )
        .expect("could not decode evidence")
    }

    fn get_oc_vcek() -> Vec<u8> {
        include_bytes!("../../test_data/oc_vcek_milan.der").to_vec()
    }
    fn default_appraisal_policy() -> Vec<u8> {
        include_bytes!("../../test_data/on-perm-reference.binarypb").to_vec()
    }

    const NOW_UTC_MILLIS: i64 = 1698829200000;

    #[test]
    fn verify_report_successful() {
        let tvs_private_key = P256Scalar::generate();
        let mut trusted_tvs = new_trusted_tvs_service(
            NOW_UTC_MILLIS,
            &hex::encode(tvs_private_key.bytes()),
            default_appraisal_policy().as_slice(),
        )
        .unwrap();
        let mut client =
            handshake::test_client::HandshakeInitiator::new(&tvs_private_key.compute_public_key());

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
            AttestReportResponse::decode(handshake_bin.as_slice()).unwrap();
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

            let mut verify_report_request_bin: Vec<u8> = Vec::with_capacity(256);
            VerifyReportRequest {
                evidence: Some(get_oc_evidence()),
                tee_certificate: get_oc_vcek(),
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
            let token_bin = trusted_tvs.verify_report(message_bin.as_slice()).unwrap();
            let message_reponse: AttestReportResponse =
                AttestReportResponse::decode(token_bin.as_slice()).unwrap();

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
    fn verify_report_invalid_report_error() {
        let tvs_private_key = P256Scalar::generate();
        let mut trusted_tvs = new_trusted_tvs_service(
            NOW_UTC_MILLIS,
            &hex::encode(tvs_private_key.bytes()),
            default_appraisal_policy().as_slice(),
        )
        .unwrap();
        let mut client =
            handshake::test_client::HandshakeInitiator::new(&tvs_private_key.compute_public_key());

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
            AttestReportResponse::decode(handshake_bin.as_slice()).unwrap();
        let handshake_response = match &message_reponse.response {
            Some(attest_report_response::Response::InitSessionResponse(init_session)) => {
                init_session.response_for_client.clone()
            }
            _ => panic!("Wrong response"),
        };

        let (_, mut client_crypter) = client.process_response(handshake_response.as_slice());

        // Test report verification.

        let mut verify_report_request_bin: Vec<u8> = Vec::with_capacity(256);
        VerifyReportRequest {
            evidence: Some(get_bad_evidence()),
            tee_certificate: get_oc_vcek(),
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
            Err(e) => assert!(e.contains("Failed to verify report. chip id differs")),
        }
    }

    #[test]
    fn new_trusted_tvs_service_error() {
        match new_trusted_tvs_service(
            NOW_UTC_MILLIS,
            &format!("{}fg", ["ff"; 31].join("")),
            default_appraisal_policy().as_slice(),
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
