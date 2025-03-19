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

use crate::proto::privacy_sandbox::server_common::hats_orchestrator_server::{
    HatsOrchestrator, HatsOrchestratorServer,
};
use crate::proto::privacy_sandbox::server_common::{GetKeysResponse, Key};
use crate::proto::privacy_sandbox::tvs::{Secret, VerifyReportResponse};
use anyhow::{anyhow, Context};
use oak_containers_orchestrator::ipc_server::{CryptoService, ServiceImplementation};
use oak_grpc::oak::containers::orchestrator_server::OrchestratorServer;
use oak_grpc::oak::containers::v1::orchestrator_crypto_server::OrchestratorCryptoServer;
use oak_proto_rust::oak::attestation::v1::Evidence;
use p256::ecdsa::SigningKey;
use prost::Message;
use secret_sharing::SecretSplit;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Mutex;
use std::{collections::HashMap, fs::Permissions};
use tokio::{fs::set_permissions, net::UnixListener};
use tokio_stream::wrappers::UnixListenerStream;
use tokio_util::sync::CancellationToken;
use tonic::{transport::Server, Request, Response};

pub mod proto {
    pub mod privacy_sandbox {
        pub mod tvs {
            include!(concat!(env!("OUT_DIR"), "/privacy_sandbox.tvs.rs"));
        }
        pub mod server_common {
            include!(concat!(
                env!("OUT_DIR"),
                "/privacy_sandbox.server_common.rs"
            ));
        }
    }
}

struct CachedGetKeysResponse {
    response: GetKeysResponse,
    expiry: std::time::Instant,
}

impl HatsServer {
    pub fn new(
        signing_key: SigningKey,
        grpc_clients: Vec<Box<dyn tvs_grpc_client::TvsClientInterface>>,
        evidence: Evidence,
        secret_split: Option<Box<dyn SecretSplit>>,
        expiry_seconds: u64,
    ) -> Self {
        Self {
            signing_key,
            grpc_clients,
            evidence,
            secret_split,
            cached_get_keys_response: Mutex::new(None),
            expiry_seconds,
        }
    }
}

pub struct HatsServer {
    signing_key: SigningKey,
    grpc_clients: Vec<Box<dyn tvs_grpc_client::TvsClientInterface>>,
    evidence: Evidence,
    secret_split: Option<Box<dyn SecretSplit>>,
    cached_get_keys_response: Mutex<Option<CachedGetKeysResponse>>,
    expiry_seconds: u64,
}

#[tonic::async_trait]
impl HatsOrchestrator for HatsServer {
    async fn get_keys(
        &self,
        _request: Request<()>,
    ) -> Result<Response<GetKeysResponse>, tonic::Status> {
        {
            //TODO: b/404823050 Extract fetch logic to independent periodic loop
            if let Ok(cached_response) = self.cached_get_keys_response.lock() {
                if let Some(cached) = &*cached_response {
                    if cached.expiry > std::time::Instant::now() {
                        return Ok(tonic::Response::new(cached.response.clone()));
                    }
                }
            }
        }
        let mut keys_temp = vec![];
        let encoded_report = get_encoded_report(
            &self.grpc_clients,
            &self.evidence,
            self.signing_key.clone(),
            self.secret_split.as_deref(),
        )
        .await
        .map_err(|error| {
            tonic::Status::internal(format!("Error getting encoded report: {:?} ", error))
        })?;

        let response =
            VerifyReportResponse::decode(encoded_report.as_slice()).map_err(|error| {
                tonic::Status::internal(format!(
                    "Error decoding VerifyReportResponse: {:?} ",
                    error
                ))
            })?;

        for secret in &response.secrets {
            keys_temp.push(Key {
                key_id: secret.key_id,
                public_key: secret.public_key.clone(),
                private_key: secret.private_key.clone(),
            });
        }
        let keys = keys_temp;
        {
            let mut cached_response = self.cached_get_keys_response.lock().unwrap();
            *cached_response = Some(CachedGetKeysResponse {
                response: GetKeysResponse { keys: keys.clone() },
                expiry: std::time::Instant::now()
                    + std::time::Duration::from_secs(self.expiry_seconds),
            });
        }

        Ok(tonic::Response::new(GetKeysResponse { keys }))
    }
}

struct KeyShares<'a> {
    public_key: String,
    shares: Vec<&'a [u8]>,
}

pub fn recover_secrets(
    response_vec: &Vec<VerifyReportResponse>,
    secret_split: Option<&dyn SecretSplit>,
) -> Result<Vec<u8>, anyhow::Error> {
    let mut recovered_secrets: Vec<Secret> = Vec::new();
    // this maps key_id to (public key, private key shares)
    let mut share_map: HashMap<i64, KeyShares> = HashMap::new();
    for response in response_vec {
        for secret in &response.secrets {
            let key_shares = share_map.entry(secret.key_id).or_insert(KeyShares {
                public_key: (*secret.public_key).to_string(),
                shares: vec![],
            });
            key_shares.shares.push(&secret.private_key);
        }
    }
    for (key_id, key_shares) in share_map {
        recovered_secrets.push(Secret {
            key_id,
            public_key: (*key_shares.public_key).to_string(),
            private_key: match secret_split {
                Some(secret_split) => secret_split
                    .recover(&key_shares.shares)
                    .map_err(|err| anyhow::anyhow!("Failed to recover the secret: {err:?}"))?,
                None => key_shares.shares[0].to_vec(),
            },
        });
    }
    let recovered_report = VerifyReportResponse {
        secrets: recovered_secrets,
    };
    let mut encoded_report: Vec<u8> = Vec::new();
    VerifyReportResponse::encode(&recovered_report, &mut encoded_report)?;
    Ok(encoded_report)
}

async fn get_encoded_report(
    tvs_grpc_clients: &Vec<Box<dyn tvs_grpc_client::TvsClientInterface>>,
    evidence: &Evidence,
    signing_key: SigningKey,
    secret_split: Option<&dyn SecretSplit>,
) -> anyhow::Result<Vec<u8>> {
    let encoded_report: Vec<u8>;
    if tvs_grpc_clients.len() > 1 {
        let mut response_vec: Vec<VerifyReportResponse> = Vec::new();
        for tvs_grpc_client in tvs_grpc_clients {
            response_vec.push(
                VerifyReportResponse::decode(
                    tvs_grpc_client
                        .send_evidence(evidence.clone(), signing_key.clone())
                        .await
                        .map_err(|error| anyhow!("couldn't fetch split tvs client: {:?}", error))?
                        .as_slice(),
                )
                .map_err(|error| anyhow!("couldn't decode VerifyReportResponse: {:?}", error))?,
            );
        }
        encoded_report = match secret_split {
            Some(secret_split) => recover_secrets(&response_vec, Some(secret_split))?,
            None => recover_secrets(&response_vec, None)?,
        };
    } else {
        encoded_report = tvs_grpc_clients[0]
            .send_evidence(evidence.clone(), signing_key.clone())
            .await
            .map_err(|error: String| anyhow!("couldn't fetch single tvs client: {:?}", error))?
    }
    Ok(encoded_report)
}

pub async fn create_services(
    path: &PathBuf,
    oak_orchestrator_server: OrchestratorServer<ServiceImplementation>,
    oak_crypto_server: OrchestratorCryptoServer<CryptoService>,
    hats_server: HatsServer,
    cancellation_token: CancellationToken,
) -> Result<(), anyhow::Error> {
    let uds = UnixListener::bind(path.clone()).context("failed to bind uds")?;
    let uds_stream = UnixListenerStream::new(uds);
    set_permissions(path, Permissions::from_mode(0o666)).await?;
    Server::builder()
        .add_service(HatsOrchestratorServer::new(hats_server))
        .add_service(oak_orchestrator_server)
        .add_service(oak_crypto_server)
        .serve_with_incoming_shutdown(uds_stream, cancellation_token.cancelled())
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::privacy_sandbox::{
        server_common::hats_orchestrator_client::HatsOrchestratorClient, tvs::Secret,
    };
    use bssl_crypto::hpke;
    use mockall::predicate::*;
    use oak_containers_attestation::generate_instance_keys;
    use tokio::net::UnixStream;
    use tonic::transport::{Endpoint, Uri};
    use tower::service_fn;
    use tvs_grpc_client::MockTvsClientInterface;

    fn get_valid_private_key() -> Vec<u8> {
        let kem = hpke::Kem::X25519HkdfSha256;
        let (_, private) = kem.generate_keypair();
        private.to_vec()
    }

    #[tokio::test]
    async fn get_key_successful() {
        let (instance_keys, _) = generate_instance_keys();
        let signing_key = instance_keys.signing_key.clone();
        let private_key = get_valid_private_key();
        // Create a MockTvsClient
        let mut mock_tvs_client = MockTvsClientInterface::new();
        let private_key_clone = private_key.clone();
        mock_tvs_client
            .expect_send_evidence()
            .with(always(), always())
            .returning(move |_, _| {
                let response = VerifyReportResponse {
                    secrets: vec![Secret {
                        key_id: 501,
                        public_key: "test-public-key1".to_string(),
                        private_key: private_key_clone.clone(),
                    }],
                };
                let mut encoded = Vec::new();
                VerifyReportResponse::encode(&response, &mut encoded).unwrap();
                Ok(encoded)
            });
        let mock_tvs_client_box =
            Box::new(mock_tvs_client) as Box<dyn tvs_grpc_client::TvsClientInterface>;
        let secret_split: Option<Box<dyn SecretSplit>> = None;
        let expiry_seconds: u64 = 3600;
        let hat_server = HatsServer::new(
            signing_key,
            vec![mock_tvs_client_box],
            Evidence::default(),
            secret_split,
            expiry_seconds,
        );
        let cancellation_token = CancellationToken::new();
        let path = PathBuf::from("/tmp/hats_test.sock");
        let path_clone = path.clone();
        let cancellation_token_clone = cancellation_token.clone();
        let server_task = tokio::spawn(async move {
            let uds = UnixListener::bind(path_clone).context("failed to bind uds");
            let uds_stream = UnixListenerStream::new(uds.expect("Reason: failed to bind uds"));
            Server::builder()
                .add_service(HatsOrchestratorServer::new(hat_server))
                .serve_with_incoming_shutdown(uds_stream, cancellation_token_clone.cancelled())
                .await
                .unwrap();
        });
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let path_str = path.as_os_str().to_str().unwrap().to_owned();

        let channel = Endpoint::try_from("http://[::]:0")
            .unwrap()
            .connect_with_connector(service_fn(move |_: Uri| {
                let path_str = path_str.clone();
                UnixStream::connect(path_str)
            }))
            .await
            .unwrap();

        let mut client = HatsOrchestratorClient::new(channel);

        let result1: GetKeysResponse = client
            .get_keys(tonic::Request::new(()))
            .await
            .unwrap()
            .into_inner();
        let result2: GetKeysResponse = client
            .get_keys(tonic::Request::new(()))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(result1, result2);

        cancellation_token.cancel();
        server_task.await.unwrap();
        // Clean up the socket file
        tokio::fs::remove_file(path).await.unwrap();
        assert_eq!(
            result1,
            GetKeysResponse {
                keys: vec![Key {
                    key_id: 501,
                    public_key: "test-public-key1".to_string(),
                    private_key,
                },],
            }
        );
    }

    #[tokio::test]
    async fn get_key_successful_multiple_clients_shamir() {
        let (instance_keys, _) = generate_instance_keys();
        let signing_key = instance_keys.signing_key.clone();
        let private_key = get_valid_private_key();

        let numshares = 3;
        let mut secret_split: Option<Box<dyn SecretSplit>> = Some(Box::new(
            secret_sharing::shamir_sharing::ShamirSharing::new(
                numshares,
                // we set the threshold to be 1 less than number of shares.
                // this is the minimum threshold for recovery.
                numshares - 1,
                secret_sharing::shamir_sharing::get_prime(),
            )
            .unwrap(),
        )
            as Box<dyn SecretSplit>);

        let shares: Vec<String> = secret_split
            .as_mut()
            .expect("Reason: secret split failed")
            .split(&private_key)
            .as_ref()
            .unwrap()
            .to_vec();

        let share1_bytes: Vec<u8> = shares
            .first()
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default();
        let share2_bytes: Vec<u8> = shares
            .get(1)
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default();
        let share3_bytes: Vec<u8> = shares
            .get(2)
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default();

        let share1_bytes_clone = share1_bytes.clone();
        let expiry_seconds: u64 = 3600;
        let share2_bytes_clone = share2_bytes.clone();
        let share3_bytes_clone = share3_bytes.clone();

        // Create MockTvsClients
        let mut mock_tvs_client1 = MockTvsClientInterface::new();
        mock_tvs_client1
            .expect_send_evidence()
            .with(always(), always())
            .returning(move |_, _| {
                let response = VerifyReportResponse {
                    secrets: vec![Secret {
                        key_id: 501,
                        public_key: "test-public-key1".to_string(),
                        private_key: share1_bytes_clone.clone(),
                    }],
                };
                let mut encoded = Vec::new();
                VerifyReportResponse::encode(&response, &mut encoded).unwrap();
                Ok(encoded)
            });
        let mock_tvs_client_box1 =
            Box::new(mock_tvs_client1) as Box<dyn tvs_grpc_client::TvsClientInterface>;

        let mut mock_tvs_client2 = MockTvsClientInterface::new();
        mock_tvs_client2
            .expect_send_evidence()
            .with(always(), always())
            .returning(move |_, _| {
                let response = VerifyReportResponse {
                    secrets: vec![Secret {
                        key_id: 501,
                        public_key: "test-public-key1".to_string(),
                        private_key: share2_bytes_clone.clone(),
                    }],
                };
                let mut encoded = Vec::new();
                VerifyReportResponse::encode(&response, &mut encoded).unwrap();
                Ok(encoded)
            });
        let mock_tvs_client_box2 =
            Box::new(mock_tvs_client2) as Box<dyn tvs_grpc_client::TvsClientInterface>;

        let mut mock_tvs_client3 = MockTvsClientInterface::new();
        mock_tvs_client3
            .expect_send_evidence()
            .with(always(), always())
            .returning(move |_, _| {
                let response = VerifyReportResponse {
                    secrets: vec![Secret {
                        key_id: 501,
                        public_key: "test-public-key1".to_string(),
                        private_key: share3_bytes_clone.clone(),
                    }],
                };
                let mut encoded = Vec::new();
                VerifyReportResponse::encode(&response, &mut encoded).unwrap();
                Ok(encoded)
            });
        let mock_tvs_client_box3 =
            Box::new(mock_tvs_client3) as Box<dyn tvs_grpc_client::TvsClientInterface>;

        let hat_server = HatsServer::new(
            signing_key,
            vec![
                mock_tvs_client_box1,
                mock_tvs_client_box2,
                mock_tvs_client_box3,
            ],
            Evidence::default(),
            secret_split,
            expiry_seconds,
        );

        let cancellation_token = CancellationToken::new();

        let path = PathBuf::from(format!("/tmp/hats_test_{}.sock", 2));
        let path_clone = path.clone();
        let cancellation_token_clone = cancellation_token.clone();
        let server_task = tokio::spawn(async move {
            let uds = UnixListener::bind(path_clone).unwrap();
            let uds_stream = UnixListenerStream::new(uds);
            Server::builder()
                .add_service(HatsOrchestratorServer::new(hat_server))
                .serve_with_incoming_shutdown(uds_stream, cancellation_token_clone.cancelled())
                .await
                .unwrap();
        });
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let path_str = path.as_os_str().to_str().unwrap().to_owned();

        let channel = Endpoint::try_from("http://[::]:0")
            .unwrap()
            .connect_with_connector(service_fn(move |_: Uri| {
                let path_str = path_str.clone();
                async move { UnixStream::connect(path_str).await }
            }))
            .await
            .unwrap();

        let mut client = HatsOrchestratorClient::new(channel);

        let result1: GetKeysResponse = client
            .get_keys(tonic::Request::new(()))
            .await
            .unwrap()
            .into_inner();

        cancellation_token.cancel();
        server_task.await.unwrap();
        // Clean up the socket file
        tokio::fs::remove_file(path).await.unwrap();
        assert_eq!(
            result1,
            GetKeysResponse {
                keys: vec![Key {
                    key_id: 501,
                    public_key: "test-public-key1".to_string(),
                    private_key: private_key.clone(),
                },],
            }
        );
    }
    #[tokio::test]
    async fn get_key_successful_multiple_clients_xor() {
        let (instance_keys, _) = generate_instance_keys();
        let signing_key = instance_keys.signing_key.clone();
        let private_key = get_valid_private_key();

        let numshares = 3;
        let mut secret_split: Option<Box<dyn SecretSplit>> = Some(Box::new(
            secret_sharing::xor_sharing::XorSharing::new(numshares).unwrap(),
        )
            as Box<dyn SecretSplit>);

        let shares: Vec<String> = secret_split
            .as_mut()
            .expect("Reason: secret split failed")
            .split(&private_key)
            .as_ref()
            .unwrap()
            .to_vec();

        let share1_bytes: Vec<u8> = shares
            .first()
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default();
        let share2_bytes: Vec<u8> = shares
            .get(1)
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default();
        let share3_bytes: Vec<u8> = shares
            .get(2)
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default();

        let share1_bytes_clone = share1_bytes.clone();
        let expiry_seconds: u64 = 3600;
        let share2_bytes_clone = share2_bytes.clone();
        let share3_bytes_clone = share3_bytes.clone();

        // Create MockTvsClients
        let mut mock_tvs_client1 = MockTvsClientInterface::new();
        mock_tvs_client1
            .expect_send_evidence()
            .with(always(), always())
            .returning(move |_, _| {
                let response = VerifyReportResponse {
                    secrets: vec![Secret {
                        key_id: 501,
                        public_key: "test-public-key1".to_string(),
                        private_key: share1_bytes_clone.clone(),
                    }],
                };
                let mut encoded = Vec::new();
                VerifyReportResponse::encode(&response, &mut encoded).unwrap();
                Ok(encoded)
            });
        let mock_tvs_client_box1 =
            Box::new(mock_tvs_client1) as Box<dyn tvs_grpc_client::TvsClientInterface>;

        let mut mock_tvs_client2 = MockTvsClientInterface::new();
        mock_tvs_client2
            .expect_send_evidence()
            .with(always(), always())
            .returning(move |_, _| {
                let response = VerifyReportResponse {
                    secrets: vec![Secret {
                        key_id: 501,
                        public_key: "test-public-key1".to_string(),
                        private_key: share2_bytes_clone.clone(),
                    }],
                };
                let mut encoded = Vec::new();
                VerifyReportResponse::encode(&response, &mut encoded).unwrap();
                Ok(encoded)
            });
        let mock_tvs_client_box2 =
            Box::new(mock_tvs_client2) as Box<dyn tvs_grpc_client::TvsClientInterface>;

        let mut mock_tvs_client3 = MockTvsClientInterface::new();
        mock_tvs_client3
            .expect_send_evidence()
            .with(always(), always())
            .returning(move |_, _| {
                let response = VerifyReportResponse {
                    secrets: vec![Secret {
                        key_id: 501,
                        public_key: "test-public-key1".to_string(),
                        private_key: share3_bytes_clone.clone(),
                    }],
                };
                let mut encoded = Vec::new();
                VerifyReportResponse::encode(&response, &mut encoded).unwrap();
                Ok(encoded)
            });
        let mock_tvs_client_box3 =
            Box::new(mock_tvs_client3) as Box<dyn tvs_grpc_client::TvsClientInterface>;

        let hat_server = HatsServer::new(
            signing_key,
            vec![
                mock_tvs_client_box1,
                mock_tvs_client_box2,
                mock_tvs_client_box3,
            ],
            Evidence::default(),
            secret_split,
            expiry_seconds,
        );

        let cancellation_token = CancellationToken::new();

        let path = PathBuf::from(format!("/tmp/hats_test_{}.sock", 3));
        let path_clone = path.clone();
        let cancellation_token_clone = cancellation_token.clone();
        let server_task = tokio::spawn(async move {
            let uds = UnixListener::bind(path_clone).unwrap();
            let uds_stream = UnixListenerStream::new(uds);
            Server::builder()
                .add_service(HatsOrchestratorServer::new(hat_server))
                .serve_with_incoming_shutdown(uds_stream, cancellation_token_clone.cancelled())
                .await
                .unwrap();
        });
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let path_str = path.as_os_str().to_str().unwrap().to_owned();

        let channel = Endpoint::try_from("http://[::]:0")
            .unwrap()
            .connect_with_connector(service_fn(move |_: Uri| {
                let path_str = path_str.clone();
                async move { UnixStream::connect(path_str).await }
            }))
            .await
            .unwrap();

        let mut client = HatsOrchestratorClient::new(channel);

        let result1: GetKeysResponse = client
            .get_keys(tonic::Request::new(()))
            .await
            .unwrap()
            .into_inner();

        cancellation_token.cancel();
        server_task.await.unwrap();
        // Clean up the socket file
        tokio::fs::remove_file(path).await.unwrap();
        assert_eq!(
            result1,
            GetKeysResponse {
                keys: vec![Key {
                    key_id: 501,
                    public_key: "test-public-key1".to_string(),
                    private_key: private_key.clone(),
                },],
            }
        );
    }
}
