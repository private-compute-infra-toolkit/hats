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
use crate::proto::privacy_sandbox::tvs::VerifyReportResponse;
use anyhow::Context;
use prost::Message;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
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

struct HatsServer {
    response: VerifyReportResponse,
}

#[tonic::async_trait]
impl HatsOrchestrator for HatsServer {
    async fn get_keys(
        &self,
        _request: Request<()>,
    ) -> Result<Response<GetKeysResponse>, tonic::Status> {
        let mut keys = vec![];
        for secret in &self.response.secrets {
            keys.push(Key {
                key_id: secret.key_id,
                public_key: secret.public_key.clone(),
                private_key: secret.private_key.clone(),
            });
        }
        Ok(tonic::Response::new(GetKeysResponse { keys: keys }))
    }
}

pub async fn create(
    path: &PathBuf,
    secrets: &[u8],
    cancellation_token: CancellationToken,
) -> Result<(), anyhow::Error> {
    // TODO(alwabel): export oak crypto service.
    let uds = UnixListener::bind(path.clone()).context("failed to bind uds")?;
    let uds_stream = UnixListenerStream::new(uds);
    set_permissions(path, Permissions::from_mode(0o666)).await?;
    // Decode TVS response.
    let response = VerifyReportResponse::decode(secrets)?;
    let hat_server = HatsServer { response: response };

    Server::builder()
        .add_service(HatsOrchestratorServer::new(hat_server))
        .serve_with_incoming_shutdown(uds_stream, cancellation_token.cancelled())
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::privacy_sandbox::server_common::hats_orchestrator_client::HatsOrchestratorClient;
    use crate::proto::privacy_sandbox::tvs::Secret;
    use futures::FutureExt;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::net::TcpListener;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::Channel;

    #[tokio::test]
    async fn get_key_successful() {
        tokio::fs::create_dir_all("/tmp/ipc").await.unwrap();
        let sockaddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let listener = TcpListener::bind(sockaddr).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let _ = tokio::spawn(async move {
            let hat_server = HatsServer {
                response: VerifyReportResponse {
                    secrets: vec![
                        Secret {
                            key_id: 501,
                            public_key: "test-public-key1".to_string(),
                            private_key: vec![0xaf, 0xbe, 0x01],
                        },
                        Secret {
                            key_id: 502,
                            public_key: "test-public-key2".to_string(),
                            private_key: vec![0xaf, 0xbe, 0x02],
                        },
                    ],
                },
            };
            tonic::transport::Server::builder()
                .add_service(HatsOrchestratorServer::new(hat_server))
                .serve_with_incoming_shutdown(
                    TcpListenerStream::new(listener),
                    shutdown_rx.map(|_| ()),
                )
                .await
        });

        let secret = tokio::spawn(async move {
            let channel = Channel::builder(format!("http://localhost:{}", port).parse().unwrap())
                .connect()
                .await
                .unwrap();
            let mut client = HatsOrchestratorClient::new(channel);
            let result: GetKeysResponse = client
                .get_keys(tonic::Request::new(()))
                .await
                .unwrap()
                .into_inner();
            result
        })
        .await;
        let _ = shutdown_tx.send(());
        assert_eq!(
            secret.unwrap(),
            GetKeysResponse {
                keys: vec![
                    Key {
                        key_id: 501,
                        public_key: "test-public-key1".to_string(),
                        private_key: vec![0xaf, 0xbe, 0x01],
                    },
                    Key {
                        key_id: 502,
                        public_key: "test-public-key2".to_string(),
                        private_key: vec![0xaf, 0xbe, 0x02],
                    },
                ],
            }
        );
    }
}
