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

use crate::proto::privacy_sandbox::client::launcher_service_client;
use crate::proto::privacy_sandbox::client::FetchOrchestratorMetadataResponse;
use crate::proto::privacy_sandbox::tvs::OpaqueMessage;
use oak_proto_rust::oak::attestation::v1::Evidence;
use p256::ecdsa::SigningKey;
use prost::Message;
use tonic::transport::Channel;
use tonic::Request;

pub mod proto {
    pub mod privacy_sandbox {
        pub mod tvs {
            include!(concat!(env!("OUT_DIR"), "/privacy_sandbox.tvs.rs"));
        }
        pub mod client {
            include!(concat!(env!("OUT_DIR"), "/privacy_sandbox.client.rs"));
        }
    }
}

pub struct TvsGrpcClient {
    inner: launcher_service_client::LauncherServiceClient<Channel>,
    tvs_public_key: String,
}

impl TvsGrpcClient {
    pub async fn create(
        addr: tonic::transport::Uri,
        tvs_public_key: String,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let channel = Channel::builder(addr.clone()).connect().await?;
        let inner = launcher_service_client::LauncherServiceClient::new(channel.clone());
        Ok(Self {
            inner,
            tvs_public_key,
        })
    }
    pub async fn create_with_channel(
        channel: tonic::transport::Channel,
        tvs_public_key: String,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let inner = launcher_service_client::LauncherServiceClient::new(channel);
        Ok(Self {
            inner,
            tvs_public_key,
        })
    }
    pub async fn fetch_orchestrator_metadata(
        &self,
    ) -> Result<FetchOrchestratorMetadataResponse, String> {
        let response = self
            .inner
            .clone()
            .fetch_orchestrator_metadata(Request::new({}))
            .await
            .map_err(|error| format!("error from launcher server: {}", error))?;
        Ok(response.into_inner())
    }
    pub async fn send_evidence(
        &self,
        evidence: Evidence,
        signing_key: SigningKey,
        vcek: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        let mut tvs = tvs_trusted_client::new_tvs_client(&self.tvs_public_key)?;

        // Channel between the `outbound stream` - the one that sends grpc
        // requests - and the `processing_task` task that generates and process VerifyReport requests:
        // handshake and sending the evidence.
        let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel(1);

        // Channel between the `inbound_task` task that gets the inbound grpc requests and the
        // the `processing_task` that process and generates Verify Report requests.
        let (inbound_tx, mut inbound_rx) = tokio::sync::mpsc::channel(1);
        let processing_task: tokio::task::JoinHandle<Result<Vec<u8>, String>> =
            tokio::spawn(async move {
                let initial_message = tvs.build_initial_message()?;
                let handshake_initial = OpaqueMessage {
                    binary_message: initial_message,
                };
                outbound_tx
                    .send(handshake_initial)
                    .await
                    .map_err(|_| "error sending requests out")?;
                let Some(handshake_response): Option<OpaqueMessage> = inbound_rx.recv().await
                else {
                    return Err("no response from the server".to_string());
                };
                tvs.process_handshake_response(handshake_response.binary_message.as_slice())?;
                let mut message: Vec<u8> = Vec::with_capacity(256);
                evidence
                    .encode(&mut message)
                    .map_err(|error| format!("error decoding evidence: {}", error))?;
                let command = tvs.build_verify_report_request(
                    message.as_slice(),
                    vcek.as_slice(),
                    &hex::encode(signing_key.to_bytes()),
                )?;
                let command = OpaqueMessage {
                    binary_message: command,
                };
                outbound_tx
                    .send(command)
                    .await
                    .map_err(|_| "error sending requests out")?;
                let Some(secret_bin) = inbound_rx.recv().await else {
                    return Err("no response from the server".to_string());
                };
                let secret = tvs.process_response(secret_bin.binary_message.as_slice())?;
                Ok(secret)
            });

        let outbound_stream = async_stream::stream! {
            while let Some(message) = outbound_rx.recv().await {
                yield message;
            }
        };
        let response = self
            .inner
            .clone()
            .verify_report(Request::new(outbound_stream))
            .await
            .map_err(|error| format!("error from tvs server: {}", error))?;

        let mut inbound = response.into_inner();
        let inbound_task: tokio::task::JoinHandle<Result<(), String>> = tokio::spawn(async move {
            loop {
                match inbound.message().await {
                    Ok(message) => match message {
                        Some(op) => {
                            inbound_tx
                                .send(op)
                                .await
                                .map_err(|_| "error sending request.")?;
                        }
                        None => break,
                    },
                    Err(e) => return Err(format!("Error {}", e)),
                }
            }
            Ok(())
        });

        inbound_task
            .await
            .unwrap()
            .map_err(|error| format!("error from tvs server: {}", error))?;
        processing_task
            .await
            .map_err(|error| format!("error from tvs server: {}", error))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::privacy_sandbox::client::launcher_service_server;
    use crate::proto::privacy_sandbox::client::FetchOrchestratorMetadataResponse;
    use crate::tests::launcher_service_server::LauncherService;
    use crate::tests::launcher_service_server::LauncherServiceServer;
    use crypto::{P256Scalar, P256_SCALAR_LENGTH};
    use futures::FutureExt;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::pin::Pin;
    use tokio::net::TcpListener;
    use tokio_stream::wrappers::TcpListenerStream;
    use tokio_stream::{wrappers::ReceiverStream, StreamExt};
    use tonic::Response;
    use tvs_trusted::proto::privacy_sandbox::tvs::AppraisalPolicies;

    struct TestService {
        pub tvs_private_key: [u8; P256_SCALAR_LENGTH],
    }

    #[tonic::async_trait]
    impl LauncherService for TestService {
        type VerifyReportStream =
            Pin<Box<dyn tokio_stream::Stream<Item = Result<OpaqueMessage, tonic::Status>> + Send>>;
        async fn fetch_orchestrator_metadata(
            &self,
            _request: tonic::Request<()>,
        ) -> Result<tonic::Response<FetchOrchestratorMetadataResponse>, tonic::Status> {
            Ok(Response::new(FetchOrchestratorMetadataResponse {
                tee_certificate_signature: include_bytes!("../../tvs/test_data/vcek_genoa.crt")
                    .to_vec(),
                noise_kk_private_key: None,
            }))
        }

        async fn verify_report(
            &self,
            request: tonic::Request<tonic::Streaming<OpaqueMessage>>,
        ) -> Result<tonic::Response<Self::VerifyReportStream>, tonic::Status> {
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            let Ok(mut trusted_tvs) = tvs_trusted::new_trusted_tvs_service(
                NOW_UTC_MILLIS,
                &self.tvs_private_key,
                default_appraisal_policies().as_slice(),
                "test_user",
            ) else {
                return Err(tonic::Status::internal("Error creating TVS Server"));
            };
            let mut stream = request.into_inner();
            let _ = tokio::spawn(async move {
                while let Some(message) = stream.next().await {
                    match message {
                        Ok(message) => {
                            let Ok(report) =
                                trusted_tvs.verify_report(message.binary_message.as_slice())
                            else {
                                let _ =
                                    tx.send(Err(tonic::Status::internal("Error verifying report")));
                                return;
                            };
                            let _ = tx
                                .send(Ok(OpaqueMessage {
                                    binary_message: report,
                                }))
                                .await;
                        }
                        Err(error) => {
                            let _ = tx.send(Err(error)).await;
                            break;
                        }
                    }
                }
            });

            Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
        }
    }

    fn default_appraisal_policies() -> Vec<u8> {
        let policy = oak_proto_rust::oak::attestation::v1::ReferenceValues::decode(
            &include_bytes!("../../tvs/test_data/on-perm-reference.binarypb")[..],
        )
        .unwrap();
        let policies = AppraisalPolicies {
            policy: vec![policy],
        };
        let mut buf: Vec<u8> = Vec::with_capacity(1024);
        policies.encode(&mut buf).unwrap();
        buf
    }

    pub fn get_good_evidence() -> oak_proto_rust::oak::attestation::v1::Evidence {
        oak_proto_rust::oak::attestation::v1::Evidence::decode(
            include_bytes!("../../tvs/test_data/good_evidence.binarypb").as_slice(),
        )
        .expect("could not decode evidence")
    }

    const NOW_UTC_MILLIS: i64 = 1698829200000;
    #[tokio::test]
    async fn verify_report_successful() {
        key_fetcher::ffi::register_echo_key_fetcher_for_test();
        let tvs_private_key = P256Scalar::generate();
        let test_service = TestService {
            tvs_private_key: tvs_private_key.bytes(),
        };
        let sockaddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let listener = TcpListener::bind(sockaddr).await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(LauncherServiceServer::new(test_service))
                .serve_with_incoming_shutdown(
                    TcpListenerStream::new(listener),
                    shutdown_rx.map(|_| ()),
                )
                .await
        });
        let secret = tokio::spawn(async move {
            let tvs_client = TvsGrpcClient::create(
                format!("http://localhost:{}", port).parse().unwrap(),
                hex::encode(tvs_private_key.compute_public_key()),
            )
            .await
            .unwrap();
            tvs_client
                .send_evidence(
                    get_good_evidence(),
                    SigningKey::from_slice(
                        &hex::decode(
                            "cf8d805ed629f4f95d20714a847773b3e53d3d8ab155e52c882646f702a98ce8",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    tvs_client
                        .fetch_orchestrator_metadata()
                        .await
                        .unwrap()
                        .tee_certificate_signature,
                )
                .await
        })
        .await;

        let _ = shutdown_tx.send(());
        let _ = server.await;
        assert_eq!(secret.unwrap().unwrap(), "test_user-secret".as_bytes());
    }

    #[tokio::test]
    async fn fetch_tee_certificate_successful() {
        key_fetcher::ffi::register_echo_key_fetcher_for_test();
        let tvs_private_key = P256Scalar::generate();
        let test_service = TestService {
            tvs_private_key: tvs_private_key.bytes(),
        };
        let sockaddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let listener = TcpListener::bind(sockaddr).await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(LauncherServiceServer::new(test_service))
                .serve_with_incoming_shutdown(
                    TcpListenerStream::new(listener),
                    shutdown_rx.map(|_| ()),
                )
                .await
        });
        let cert = tokio::spawn(async move {
            let tvs_client = TvsGrpcClient::create(
                format!("http://localhost:{}", port).parse().unwrap(),
                hex::encode(tvs_private_key.compute_public_key()),
            )
            .await
            .unwrap();
            tvs_client.fetch_orchestrator_metadata().await
        })
        .await;

        let _ = shutdown_tx.send(());
        let _ = server.await;
        let want = include_bytes!("../../tvs/test_data/vcek_genoa.crt").to_vec();
        assert_eq!(
            cert.unwrap().unwrap(),
            proto::privacy_sandbox::client::FetchOrchestratorMetadataResponse {
                tee_certificate_signature: want,
                noise_kk_private_key: None,
            }
        )
    }
}
