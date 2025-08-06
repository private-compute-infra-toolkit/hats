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

use anyhow::Context;
use client_proto::pcit::server_common::{
    hats_orchestrator_server::{HatsOrchestrator, HatsOrchestratorServer},
    GetKeysResponse, Key,
};
use oak_containers_orchestrator::ipc_server::{CryptoService, ServiceImplementation};
use oak_grpc::oak::containers::orchestrator_server::OrchestratorServer;
use oak_grpc::oak::containers::v1::orchestrator_crypto_server::OrchestratorCryptoServer;
use prost::Message;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use tokio::{fs::set_permissions, net::UnixListener};
use tokio_stream::wrappers::UnixListenerStream;
use tokio_util::sync::CancellationToken;
use tonic::{transport::Server, Request, Response};
use tvs_proto::pcit::tvs::VerifyReportResponse;

impl HatsServer {
    pub fn new(tvs_secret_manager: Box<dyn tvs_secret_manager::TvsSecretManagerInterface>) -> Self {
        Self { tvs_secret_manager }
    }
}

pub struct HatsServer {
    tvs_secret_manager: Box<dyn tvs_secret_manager::TvsSecretManagerInterface>,
}

#[tonic::async_trait]
impl HatsOrchestrator for HatsServer {
    async fn get_keys(
        &self,
        _request: Request<()>,
    ) -> Result<Response<GetKeysResponse>, tonic::Status> {
        let mut keys_temp = vec![];
        let encoded_report =
            self.tvs_secret_manager
                .get_encoded_report()
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
                key_id: secret.key_id.clone(),
                public_key: secret.public_key.clone(),
                private_key: secret.private_key.clone(),
            });
        }
        let keys = keys_temp;

        Ok(tonic::Response::new(GetKeysResponse { keys }))
    }
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
    use anyhow::anyhow;
    use tvs_proto::pcit::tvs::Secret;
    use tvs_secret_manager::MockTvsSecretManagerInterface;

    #[tokio::test]
    async fn test_get_keys() {
        let mut mock_tvs_secret_manager = MockTvsSecretManagerInterface::new();
        mock_tvs_secret_manager
            .expect_get_encoded_report()
            .returning(|| {
                let response = VerifyReportResponse {
                    secrets: vec![Secret {
                        key_id: "501".to_string(),
                        public_key: "test-public-key1".to_string(),
                        private_key: vec![1, 2, 3],
                    }],
                };
                let mut encoded = Vec::new();
                VerifyReportResponse::encode(&response, &mut encoded).unwrap();
                Ok(encoded)
            });
        let hats_server = HatsServer::new(Box::new(mock_tvs_secret_manager));
        let request = Request::new(());
        let response = hats_server.get_keys(request).await.unwrap();
        let keys = response.into_inner().keys;
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_id, "501".to_string());
        assert_eq!(keys[0].public_key, "test-public-key1");
        assert_eq!(keys[0].private_key, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn test_get_keys_error() {
        let mut mock_tvs_secret_manager = MockTvsSecretManagerInterface::new();
        mock_tvs_secret_manager
            .expect_get_encoded_report()
            .returning(|| Err(anyhow!("Error getting encoded report")));
        let hats_server = HatsServer::new(Box::new(mock_tvs_secret_manager));
        let request = Request::new(());
        let response = hats_server.get_keys(request).await;
        assert!(response.is_err());
    }
}
