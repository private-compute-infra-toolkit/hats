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
use key_provider::KeyProvider;
use policy_manager::PolicyManager;
use tvs_enclave::proto::privacy_sandbox::tvs::{
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
            Arc::clone(&self.policy_manager),
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
    user_ids_by_key: BTreeMap<Vec<u8>, i64>,
    user_secrets_by_id: BTreeMap<i64, Vec<u8>>,
}

impl KeyFetcherService {
    pub(crate) fn register_or_update_user(&mut self, request: RegisterOrUpdateUserRequest) {
        self.user_ids_by_key
            .insert(request.authentication_key, request.id);
        self.user_secrets_by_id.insert(request.id, request.secret);
    }
}

impl key_provider::KeyProvider for KeyFetcherService {
    fn get_primary_private_key(&self) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("unimplemented")
    }

    fn get_secondary_private_key(&self) -> Option<anyhow::Result<Vec<u8>>> {
        None
    }

    fn user_id_for_authentication_key(&self, public_key: &[u8]) -> anyhow::Result<i64> {
        let Some(id) = self.user_ids_by_key.get(public_key) else {
            anyhow::bail!("user public key is not registered");
        };
        Ok(*id)
    }

    fn get_secrets_for_user_id(&self, user_id: i64) -> anyhow::Result<Vec<u8>> {
        let Some(secret) = self.user_secrets_by_id.get(&user_id) else {
            anyhow::bail!("no secret found for the user");
        };
        Ok(secret.to_vec())
    }
}
