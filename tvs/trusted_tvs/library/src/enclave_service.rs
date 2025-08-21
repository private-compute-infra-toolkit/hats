// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

extern crate alloc;
use crate::request_handler::RequestHandler;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use crypto::{P256Scalar, P256_SCALAR_LENGTH, P256_X962_LENGTH};
use policy_manager::PolicyManager;
use trusted_tvs_types::{EvidenceValidator, KeyProvider};
use tvs_enclave::proto::pcit::tvs::{
    CreateSessionRequest, CreateSessionResponse, DoCommandRequest, DoCommandResponse,
    LoadAppraisalPoliciesRequest, ProvisionKeysRequest, RegisterOrUpdateUserRequest,
    TerminateSessionRequest, TvsEnclave,
};

/// Implement TvsEnclave MicroRpc service to run TVS in Oak's restricted kernel.
///
/// The service is exported to the untrusted part (launcher) to pass requests
/// it receives from the Internet.
/// The service receives attestation report generated from secure hardware,
/// validates that the report is signed by a trusted party e.g. secure hardware,
/// and that the measurements matches the one in the appraisal policies loaded
/// in the `policy_manager`.
/// Upon successful validation, the client is given a set of tokens e.g. private
/// HPKE keys so that they can process user data.
/// The service expect messages to be encrypted using noise KK in the application
/// layer so that the requests are encrypted end-to-end.
/// For each session, the services returns a `session_id` that should be attached
/// to all messages belonging to the same session.
pub struct EnclaveService {
    request_handlers: BTreeMap<Vec<u8>, RequestHandler>,
    primary_private_key: Arc<P256Scalar>,
    primary_public_key: [u8; P256_X962_LENGTH],
    key_provider: Arc<KeyFetcherService>,
    policy_manager: Arc<PolicyManager>,
}

impl EnclaveService {
    /// Create a new enclave service.
    pub fn new() -> anyhow::Result<Self> {
        let policy_manager = Arc::new(PolicyManager::new(
            /*enable_policy_signature=*/ true, /*accept_insecure_policies=*/ false,
        ));

        // Start with identity key that we expect the launcher to update.
        let primary_private_key: P256Scalar = get_identity_key()
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to initialize primary private key"))?;
        let primary_public_key = primary_private_key.compute_public_key();
        Ok(Self {
            request_handlers: BTreeMap::new(),
            key_provider: Arc::new(KeyFetcherService::default()),
            policy_manager,
            primary_private_key: Arc::new(primary_private_key),
            primary_public_key,
        })
    }
}

// Use arbitrary time stamp in the past, as the attestation verification library
// does ignore time for now.
const NOW_UTC_MILLIS: i64 = 1732062397340;

impl TvsEnclave for EnclaveService {
    /// Provide a private key to be used in the noise handshake.
    /// The untrusted part (launcher) should pass in the private key.
    fn provision_keys(&mut self, request: ProvisionKeysRequest) -> Result<(), micro_rpc::Status> {
        let primary_private_key: P256Scalar = request
            .private_key
            .as_slice()
            .try_into()
            .map_err(|_| micro_rpc::Status::new(micro_rpc::StatusCode::InvalidArgument))?;
        self.primary_public_key = primary_private_key.compute_public_key();
        self.primary_private_key = Arc::new(primary_private_key);
        Ok(())
    }

    /// Provide appraisal policies to be used in validating measurements in the
    /// attestation report provided by the client.
    /// The untrusted part (launcher) should pass in the appraisal policies.
    /// Appraisal policies should be properly signed in order to be accepted.
    fn load_appraisal_policies(
        &mut self,
        request: LoadAppraisalPoliciesRequest,
    ) -> Result<(), micro_rpc::Status> {
        Arc::<PolicyManager>::make_mut(&mut self.policy_manager)
            .update(&request.policies)
            .map_err(|_| micro_rpc::Status::new(micro_rpc::StatusCode::InvalidArgument))?;
        Ok(())
    }

    /// Register user authentication key and secrets to be returned upon
    /// successful attestation validation.
    fn register_or_update_user(
        &mut self,
        request: RegisterOrUpdateUserRequest,
    ) -> Result<(), micro_rpc::Status> {
        Arc::<KeyFetcherService>::make_mut(&mut self.key_provider).register_or_update_user(request);
        Ok(())
    }

    /// Create a new session by initiating a new noise KK session.
    /// The RPC returns a session id and an ephemeral public key.
    /// The user id should be attached to all messages in the same session.
    /// The ephemeral key is used to encrypt/decrypt messages.
    fn create_session(
        &mut self,
        request: CreateSessionRequest,
    ) -> Result<CreateSessionResponse, micro_rpc::Status> {
        // For now, we use a hard-coded time value from the past.
        let mut request_handler = RequestHandler::new(
            NOW_UTC_MILLIS,
            self.primary_private_key.clone(),
            &self.primary_public_key,
            None,
            None,
            Arc::clone(&self.policy_manager) as Arc<dyn EvidenceValidator>,
            Arc::clone(&self.key_provider) as Arc<dyn KeyProvider>,
            /*user=*/ "",
        );
        let response = request_handler
            .verify_report(&request.binary_message)
            .map_err(|err| {
                micro_rpc::Status::new_with_message(
                    micro_rpc::StatusCode::Internal,
                    format!("failed to initiate a session: {err}"),
                )
            })?;
        let session_id = request_handler.handshake_hash();
        self.request_handlers
            .insert(session_id.clone(), request_handler);
        Ok(CreateSessionResponse {
            session_id,
            binary_message: response,
        })
    }

    /// Process user command (validate attestation report), and secrets e.g.
    /// HPKE private keys so the client can process user traffic.
    fn do_command(
        &mut self,
        request: DoCommandRequest,
    ) -> Result<DoCommandResponse, micro_rpc::Status> {
        let Some(request_handler) = self.request_handlers.get_mut(&request.session_id) else {
            return Err(micro_rpc::Status::new_with_message(
                micro_rpc::StatusCode::NotFound,
                "failed to find the session",
            ));
        };
        let response = request_handler
            .verify_report(&request.binary_message)
            .map_err(|err| {
                micro_rpc::Status::new_with_message(
                    micro_rpc::StatusCode::Internal,
                    format!("failed to process request: {err}"),
                )
            })?;
        Ok(DoCommandResponse {
            binary_message: response,
        })
    }

    /// Terminate a session by removing all data for the given session.
    /// Failure to terminate session might caused the server to run out of
    /// memory and fail to process further requests.
    fn terminate_session(
        &mut self,
        request: TerminateSessionRequest,
    ) -> Result<(), micro_rpc::Status> {
        if self.request_handlers.remove(&request.session_id).is_none() {
            return Err(micro_rpc::Status::new_with_message(
                micro_rpc::StatusCode::NotFound,
                "failed to remove session. The session does not exist",
            ));
        }
        Ok(())
    }
}

fn get_identity_key() -> [u8; P256_SCALAR_LENGTH] {
    let mut key = [0u8; P256_SCALAR_LENGTH];
    key[key.len() - 1] = 1;
    key
}

#[derive(Clone, Default)]
struct KeyFetcherService {
    user_ids_by_key: BTreeMap<Vec<u8>, Vec<u8>>,
    user_secrets_by_id: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl KeyFetcherService {
    pub(crate) fn register_or_update_user(&mut self, request: RegisterOrUpdateUserRequest) {
        self.user_ids_by_key
            .insert(request.authentication_key, request.id.clone());
        self.user_secrets_by_id.insert(request.id, request.secret);
    }
}

impl KeyProvider for KeyFetcherService {
    fn get_primary_private_key(&self) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("unimplemented")
    }

    fn get_secondary_private_key(&self) -> Option<anyhow::Result<Vec<u8>>> {
        None
    }

    fn user_id_for_authentication_key(&self, public_key: &[u8]) -> anyhow::Result<Vec<u8>> {
        let Some(id) = self.user_ids_by_key.get(public_key) else {
            anyhow::bail!("user public key is not registered");
        };
        Ok(id.to_vec())
    }

    fn get_secrets_for_user_id(&self, user_id: &[u8]) -> anyhow::Result<Vec<u8>> {
        let Some(secret) = self.user_secrets_by_id.get(user_id) else {
            anyhow::bail!("no secret found for the user");
        };
        Ok(secret.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::P256Scalar;
    use oak_proto_rust::oak::attestation::v1::TcbVersion;
    use prost::Message;
    #[cfg(feature = "dynamic_attestation")]
    use test_utils_rs::create_dynamic_genoa_policy;
    use tvs_proto::pcit::tvs::{
        stage0_measurement, AmdSev, AppraisalPolicies, AppraisalPolicy, Measurement,
        Signature as PolicySignature, Stage0Measurement,
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
        // Select which appriasal policies to use based on dynamic_attestation flag
        let policies = {
            #[cfg(feature = "dynamic_attestation")]
            {
                create_dynamic_genoa_policy()
            }
            #[cfg(not(feature = "dynamic_attestation"))]
            {
                default_appraisal_policies()
            }
        };
        let tvs_private_key = P256Scalar::generate();
        let client_private_key = P256Scalar::generate();
        let mut service = EnclaveService::new().unwrap();

        // Provision the TVS keys.
        service
            .provision_keys(ProvisionKeysRequest {
                private_key: tvs_private_key.bytes().to_vec(),
            })
            .unwrap();

        // Load the appraisal policies.
        service
            .load_appraisal_policies(LoadAppraisalPoliciesRequest { policies })
            .unwrap();

        // Register a user.
        service
            .register_or_update_user(RegisterOrUpdateUserRequest {
                id: b"1".to_vec(),
                authentication_key: client_private_key.compute_public_key().to_vec(),
                secret: b"secret".to_vec(),
            })
            .unwrap();

        let mut tvs_client = TvsClient::new(
            &client_private_key.bytes(),
            &tvs_private_key.compute_public_key(),
        )
        .unwrap();

        // Create a session (do handshake).
        let create_session_response = service
            .create_session(CreateSessionRequest {
                binary_message: tvs_client.build_initial_message().unwrap(),
            })
            .unwrap();

        let session_id = create_session_response.session_id;

        tvs_client
            .process_handshake_response(&create_session_response.binary_message)
            .unwrap();

        // Send the attestation report and get the secret.
        let do_command_response = service
            .do_command(DoCommandRequest {
                session_id: session_id.clone(),
                binary_message: tvs_client
                    .build_verify_report_request(
                        &get_evidence_v1_genoa(),
                        &get_genoa_vcek(),
                        /*application_signing_key=*/
                        "be828103ab28b93a5d91592d69374541d6e7decd287ef7df1f990a87f231cb8c",
                    )
                    .unwrap(),
            })
            .unwrap();

        assert_eq!(
            tvs_client
                .process_response(&do_command_response.binary_message)
                .unwrap(),
            b"secret"
        );

        service
            .terminate_session(TerminateSessionRequest { session_id })
            .unwrap();
    }

    #[test]
    fn verify_report_invalid_report_error() {
        init_logger();
        let tvs_private_key = P256Scalar::generate();
        let client_private_key = P256Scalar::generate();
        let mut service = EnclaveService::new().unwrap();

        // Provision the TVS keys.
        service
            .provision_keys(ProvisionKeysRequest {
                private_key: tvs_private_key.bytes().to_vec(),
            })
            .unwrap();

        // Load the appraisal policies.
        service
            .load_appraisal_policies(LoadAppraisalPoliciesRequest {
                policies: default_appraisal_policies(),
            })
            .unwrap();

        // Register a user.
        service
            .register_or_update_user(RegisterOrUpdateUserRequest {
                id: b"1".to_vec(),
                authentication_key: client_private_key.compute_public_key().to_vec(),
                secret: b"secret".to_vec(),
            })
            .unwrap();

        let mut tvs_client = TvsClient::new(
            &client_private_key.bytes(),
            &tvs_private_key.compute_public_key(),
        )
        .unwrap();

        // Create a session (do handshake).
        let create_session_response = service
            .create_session(CreateSessionRequest {
                binary_message: tvs_client.build_initial_message().unwrap(),
            })
            .unwrap();

        let session_id = create_session_response.session_id;

        tvs_client
            .process_handshake_response(&create_session_response.binary_message)
            .unwrap();

        match service.do_command(DoCommandRequest {
            session_id: session_id.clone(),
            binary_message: tvs_client
                .build_verify_report_request(
                    &get_evidence_v2_genoa(),
                    &get_genoa_vcek(),
                    /*application_signing_key=*/
                    "90c6593892237eb36a525902340c02a6865a13e37ed9eb73b5123b312a0bb3b0",
                )
                .unwrap(),
        }) {
            Ok(_) => panic!("verify_command() should fail."),
            Err(e) => {
                assert!(e
                    .to_string()
                    .contains("Failed to verify report. No matching appraisal policy found"))
            }
        }

        service
            .terminate_session(TerminateSessionRequest { session_id })
            .unwrap();
    }
}
