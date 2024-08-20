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
    tvs_public_key: Vec<u8>,
    tvs_authentication_key: Option<Vec<u8>>,
    tee_certificate: Option<Vec<u8>>,
}

impl TvsGrpcClient {
    pub async fn create(
        addr: tonic::transport::Uri,
        tvs_public_key: Vec<u8>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let channel = Channel::builder(addr.clone()).connect().await?;
        let inner = launcher_service_client::LauncherServiceClient::new(channel.clone());
        let mut tvs_grp_client = Self {
            inner,
            tvs_public_key,
            tvs_authentication_key: None,
            tee_certificate: None,
        };
        tvs_grp_client.init().await?;
        Ok(tvs_grp_client)
    }

    pub async fn create_with_channel(
        channel: tonic::transport::Channel,
        tvs_public_key: Vec<u8>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let inner = launcher_service_client::LauncherServiceClient::new(channel);
        let mut tvs_grp_client = Self {
            inner,
            tvs_public_key,
            tvs_authentication_key: None,
            tee_certificate: None,
        };
        tvs_grp_client.init().await?;
        Ok(tvs_grp_client)
    }

    // Get metadata from the launcher.
    async fn init(&mut self) -> Result<(), String> {
        let metadata = self
            .fetch_orchestrator_metadata()
            .await
            .map_err(|error| format!("couldn't find tee metadata: {:?}", error))?;
        self.tee_certificate = Some(metadata.tee_certificate);
        self.tvs_authentication_key = Some(metadata.tvs_authentication_key);
        Ok(())
    }

    async fn fetch_orchestrator_metadata(
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
    ) -> Result<Vec<u8>, String> {
        let Some(ref tvs_authentication_key) = self.tvs_authentication_key else {
            return Err("tvs_authentication_key is not set".to_string());
        };
        let Some(ref tee_certificate) = self.tee_certificate else {
            return Err("tee_certificate is not set".to_string());
        };
        self.send_evidence_internal(
            evidence,
            signing_key,
            tvs_authentication_key.to_vec(),
            tee_certificate.to_vec(),
        )
        .await
    }
    async fn send_evidence_internal(
        &self,
        evidence: Evidence,
        signing_key: SigningKey,
        tvs_authentication_key: Vec<u8>,
        tee_certificate: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        let mut tvs =
            tvs_trusted_client::new_tvs_client(&tvs_authentication_key, &self.tvs_public_key)?;

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
                    return Err("error from the server".to_string());
                };
                tvs.process_handshake_response(handshake_response.binary_message.as_slice())?;
                let mut message: Vec<u8> = Vec::with_capacity(256);
                evidence
                    .encode(&mut message)
                    .map_err(|error| format!("error decoding evidence: {}", error))?;
                let command = tvs.build_verify_report_request(
                    message.as_slice(),
                    tee_certificate.as_slice(),
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
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::pin::Pin;
    use tokio::net::TcpListener;
    use tokio_stream::wrappers::TcpListenerStream;
    use tokio_stream::{wrappers::ReceiverStream, StreamExt};
    use tonic::Response;
    use tvs_trusted::proto::privacy_sandbox::tvs::{
        AppraisalPolicies, Secret, VerifyReportResponse,
    };

    struct TestLauncherService {
        pub tvs_private_key: [u8; P256_SCALAR_LENGTH],
        pub tvs_authentication_key: Vec<u8>,
    }

    #[tonic::async_trait]
    impl LauncherService for TestLauncherService {
        type VerifyReportStream =
            Pin<Box<dyn tokio_stream::Stream<Item = Result<OpaqueMessage, tonic::Status>> + Send>>;
        async fn fetch_orchestrator_metadata(
            &self,
            _request: tonic::Request<()>,
        ) -> Result<tonic::Response<FetchOrchestratorMetadataResponse>, tonic::Status> {
            Ok(Response::new(FetchOrchestratorMetadataResponse {
                tee_certificate: include_bytes!("../../tvs/test_data/vcek_genoa.crt").to_vec(),
                tvs_authentication_key: self.tvs_authentication_key.to_vec(),
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

    #[tokio::test]
    async fn verify_report_successful() {
        key_fetcher::ffi::register_echo_key_fetcher_for_test();
        let tvs_private_key = P256Scalar::generate();
        let tvs_authentication_key = get_good_client_private_key();
        let test_service = TestLauncherService {
            tvs_private_key: tvs_private_key.bytes(),
            tvs_authentication_key: tvs_authentication_key.bytes().to_vec(),
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
                tvs_private_key.compute_public_key().to_vec(),
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
                )
                .await
        })
        .await;

        let _ = shutdown_tx.send(());
        let _ = server.await;
        let response =
            VerifyReportResponse::decode(VecDeque::from(secret.unwrap().unwrap())).unwrap();
        assert_eq!(response, expected_verify_report_response(/*user_id=*/ 1));
    }

    #[tokio::test]
    async fn verify_report_unauthenticated_error() {
        key_fetcher::ffi::register_echo_key_fetcher_for_test();
        let tvs_private_key = P256Scalar::generate();
        let test_service = TestLauncherService {
            tvs_private_key: tvs_private_key.bytes(),
            tvs_authentication_key: P256Scalar::generate().bytes().to_vec(),
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
                tvs_private_key.compute_public_key().to_vec(),
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
                )
                .await
        })
        .await;

        let _ = shutdown_tx.send(());
        let _ = server.await;
        match secret.unwrap() {
            Ok(_) => assert!(false, "send_evidence() should fail."),
            Err(_) => assert!(true),
        }
    }

    #[tokio::test]
    async fn fetch_tee_certificate_successful() {
        key_fetcher::ffi::register_echo_key_fetcher_for_test();
        let tvs_private_key = P256Scalar::generate();
        let test_service = TestLauncherService {
            tvs_private_key: tvs_private_key.bytes(),
            tvs_authentication_key: vec![],
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
                tvs_private_key.compute_public_key().to_vec(),
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
                tee_certificate: want,
                tvs_authentication_key: vec![],
            }
        )
    }
}
