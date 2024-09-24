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

use crate::proto::privacy_sandbox::tvs::{
    attest_report_request, attest_report_response, AttestReportRequest, AttestReportResponse,
    InitSessionRequest, VerifyReportRequest, VerifyReportRequestEncrypted,
};
use crypto::{P256Scalar, P256_SCALAR_LENGTH, P256_X962_LENGTH, SHA256_OUTPUT_LEN};
use handshake::{client::HandshakeInitiator, noise::HandshakeType, Crypter};
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
    struct TvsClientCreationResult {
        value: *mut TvsClient,
        error: String,
    }

    struct VecU8Result {
        value: Vec<u8>,
        error: String,
    }

    extern "Rust" {
        type TvsClient;

        // This is to force cxx to generate full implementation
        // for Box<TvsClient>::drop()
        fn tvs_client_dummy() -> Result<Box<TvsClient>>;

        #[cxx_name = "NewTvsClient"]
        fn new_tvs_client(private_key: &[u8], tvs_pub_key: &[u8]) -> TvsClientCreationResult;

        #[cxx_name = "BuildInitialMessage"]
        fn build_initial_message_ffi(&mut self) -> VecU8Result;

        #[cxx_name = "ProcessHandshakeResponse"]
        fn process_handshake_response_ffi(&mut self, response: &[u8]) -> String;

        #[cxx_name = "BuildVerifyReportRequest"]
        fn build_verify_report_request_ffi(
            &mut self,
            evidence_bin: &[u8],
            vcek: &[u8],
            application_signing_key: &str,
        ) -> VecU8Result;

        #[cxx_name = "ProcessResponse"]
        fn process_response_ffi(&mut self, response: &[u8]) -> VecU8Result;
    }
}

#[cfg(not(feature = "noffi"))]
fn tvs_client_dummy() -> Result<Box<TvsClient>, String> {
    Err("unimplemented".to_string())
}

#[cfg(not(feature = "noffi"))]
fn new_tvs_client(private_key: &[u8], tvs_public_key: &[u8]) -> ffi::TvsClientCreationResult {
    match TvsClient::new(private_key, tvs_public_key) {
        Ok(tvs_client) => ffi::TvsClientCreationResult {
            value: Box::into_raw(Box::new(tvs_client)),
            error: "".to_string(),
        },
        Err(error) => ffi::TvsClientCreationResult {
            value: std::ptr::null_mut(),
            error: error,
        },
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

    // Wrapper around `build_initial_message` to be used in C++.
    #[cfg(not(feature = "noffi"))]
    fn build_initial_message_ffi(&mut self) -> ffi::VecU8Result {
        match self.build_initial_message() {
            Ok(result) => ffi::VecU8Result {
                value: result,
                error: "".to_string(),
            },
            Err(error) => ffi::VecU8Result {
                value: vec![],
                error: error,
            },
        }
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

    // Wrapper around `process_handshake_response` to be used in C++.
    #[cfg(not(feature = "noffi"))]
    fn process_handshake_response_ffi(&mut self, response: &[u8]) -> String {
        match self.process_handshake_response(response) {
            Ok(_) => "".to_string(),
            Err(error) => error,
        }
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

    // Wrapper around `build_verify_report_request` to be used in C++.
    #[cfg(not(feature = "noffi"))]
    fn build_verify_report_request_ffi(
        &mut self,
        evidence_bin: &[u8],
        vcek: &[u8],
        application_signing_key: &str,
    ) -> ffi::VecU8Result {
        match self.build_verify_report_request(evidence_bin, vcek, application_signing_key) {
            Ok(result) => ffi::VecU8Result {
                value: result,
                error: "".to_string(),
            },
            Err(error) => ffi::VecU8Result {
                value: vec![],
                error: error,
            },
        }
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

    // Wrapper around `process_response` to be used in C++.
    #[cfg(not(feature = "noffi"))]
    fn process_response_ffi(&mut self, response: &[u8]) -> ffi::VecU8Result {
        match self.process_response(response) {
            Ok(result) => ffi::VecU8Result {
                value: result,
                error: "".to_string(),
            },
            Err(error) => ffi::VecU8Result {
                value: vec![],
                error: error,
            },
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
    use tvs_trusted::proto::privacy_sandbox::tvs::{
        appraisal_policies::SignedAppraisalPolicy, AppraisalPolicies, Secret, VerifyReportResponse,
    };

    fn get_genoa_vcek() -> Vec<u8> {
        include_bytes!("../test_data/vcek_genoa.crt").to_vec()
    }

    fn default_appraisal_policies() -> Vec<u8> {
        let signed_policy = SignedAppraisalPolicy::decode(
            &include_bytes!("../../tvs/test_data/on-perm-reference.binarypb")[..],
        )
        .unwrap();
        let policies = AppraisalPolicies {
            signed_policy: vec![signed_policy],
        };
        let mut buf: Vec<u8> = Vec::with_capacity(1024);
        policies.encode(&mut buf).unwrap();
        buf
    }

    fn get_good_evidence() -> Vec<u8> {
        include_bytes!("../test_data/good_evidence.binarypb").to_vec()
    }

    fn expected_verify_report_response(user_id: i64) -> VerifyReportResponse {
        VerifyReportResponse {
            secrets: vec![Secret {
                key_id: 64,
                public_key: format!("{user_id}-public-key").into(),
                private_key: format!("{user_id}-secret").into(),
            }],
        }
    }

    // Get client keys where the public key is registered in the test key fetcher.
    fn get_good_client_private_key() -> P256Scalar {
        static TEST_CLIENT_PRIVATE_KEY: &'static str =
            "750fa48f4ddaf3201d4f1d2139878abceeb84b09dc288c17e606640eb56437a2";
        return hex::decode(TEST_CLIENT_PRIVATE_KEY)
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();
    }

    const NOW_UTC_MILLIS: i64 = 1698829200000;

    // End to end testing: handshake, building and signing the report and decrypt the secret.
    #[test]
    fn verify_report_successful() {
        key_fetcher::ffi::register_echo_key_fetcher_for_test();
        let tvs_private_key = P256Scalar::generate();
        let mut trusted_tvs_service = tvs_trusted::TrustedTvs::new(
            NOW_UTC_MILLIS,
            &tvs_private_key.bytes(),
            /*secondary_private_key=*/ None,
            default_appraisal_policies().as_slice(),
            "test_user1",
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
        )
        .unwrap();

        let client_private_key = get_good_client_private_key();
        let mut tvs_client = TvsClient::new(
            &client_private_key.bytes(),
            &tvs_private_key.compute_public_key(),
        )
        .unwrap();
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
        let response = VerifyReportResponse::decode(decrypted_secret.as_slice()).unwrap();
        assert_eq!(response, expected_verify_report_response(/*user_id=*/ 1));
    }

    #[test]
    fn process_handshake_response_error() {
        key_fetcher::ffi::register_echo_key_fetcher_for_test();
        let client_private_key = get_good_client_private_key();
        let tvs_private_key = P256Scalar::generate();
        let mut tvs_client = TvsClient::new(
            &client_private_key.bytes(),
            &tvs_private_key.compute_public_key(),
        )
        .unwrap();
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
        key_fetcher::ffi::register_echo_key_fetcher_for_test();
        let client_private_key = get_good_client_private_key();
        let tvs_private_key = P256Scalar::generate();
        let mut tvs_client = TvsClient::new(
            &client_private_key.bytes(),
            &tvs_private_key.compute_public_key(),
        )
        .unwrap();
        match tvs_client.process_response(&[1, 2, 3]) {
            Ok(_) => assert!(false, "process_response() should fail"),
            Err(e) => assert_eq!(
                e,
                "Handshake initiation should be done before encrypting messages."
            ),
        }

        let mut trusted_tvs_service = tvs_trusted::TrustedTvs::new(
            NOW_UTC_MILLIS,
            &tvs_private_key.bytes(),
            /*secondary_private_key=*/ None,
            default_appraisal_policies().as_slice(),
            "test_user2",
            /*enable_policy_signature=*/ true,
            /*accept_insecure_policies=*/ false,
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
        key_fetcher::ffi::register_echo_key_fetcher_for_test();
        let tvs_private_key = P256Scalar::generate();
        match TvsClient::new(&[1, 2, 3], &tvs_private_key.compute_public_key()) {
            Ok(_) => assert!(false, "TvsClient::new() should fail"),
            Err(e) => assert_eq!(e, "Invalid private key. Key should be 32 bytes long.",),
        }
        let client_private_key = get_good_client_private_key();
        match TvsClient::new(&client_private_key.bytes(), &[1, 2, 3]) {
            Ok(_) => assert!(false, "TvsClient::new() should fail"),
            Err(e) => assert_eq!(
                e,
                format!("Expected tvs_public_key to be of length {P256_X962_LENGTH}."),
            ),
        }
    }
}
