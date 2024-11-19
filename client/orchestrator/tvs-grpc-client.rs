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
use crate::proto::privacy_sandbox::client::ForwardingTvsMessage;
use crate::proto::privacy_sandbox::tvs::OpaqueMessage;
use anyhow::Context;
use oak_proto_rust::oak::attestation::v1::Evidence;
use p256::ecdsa::SigningKey;
use prost::Message;
use tokio_vsock::{VsockAddr, VsockStream};
use tonic::transport::Channel;
use tonic::Request;
use tower::service_fn;

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
    tvs_id: i64,

    // If specified, first key is primary key used for encryption/decryption of private key.
    // Additional keys are used only for decryption (to facilitate key rotation).
    private_key_wrapping_keys: Vec<Vec<u8>>,
}

impl TvsGrpcClient {
    pub async fn create(
        addr: tonic::transport::Uri,
        tvs_public_key: Vec<u8>,
        tvs_id: i64,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let channel = if addr.scheme_str() == Some("vsock") {
            let vsock_addr = VsockAddr::new(
                addr.host()
                    .unwrap_or(format!("{}", tokio_vsock::VMADDR_CID_HOST).as_str())
                    .parse()
                    .context("invalid vsock CID")?,
                addr.authority()
                    .context("failed to extract authority from vsock address")?
                    .as_str()
                    .split(':')
                    .last()
                    .context("failed to extract port from vsock address")?
                    .parse::<u32>()
                    .context("invalid vsock port")?,
            );
            // Channel builder does not handle non-TCP URIs very well.
            // When passing vSock or UDS URI it creates a TCP channel.
            // Here we pass a fake URI schema so that it fails and falls
            // back to connect_with_connector where we create a vSock stream.
            // https://github.com/hyperium/tonic/issues/608
            Channel::builder(tonic::transport::Uri::from_static("http://0:0"))
                .connect_with_connector(service_fn(move |_| VsockStream::connect(vsock_addr)))
                .await?
        } else {
            Channel::builder(addr.clone()).connect().await?
        };
        TvsGrpcClient::create_with_channel(channel.clone(), tvs_public_key, tvs_id).await
    }

    pub async fn create_with_channel(
        channel: tonic::transport::Channel,
        tvs_public_key: Vec<u8>,
        tvs_id: i64,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let inner = launcher_service_client::LauncherServiceClient::new(channel);
        let mut tvs_grp_client = Self {
            inner,
            tvs_public_key,
            tvs_authentication_key: None,
            tee_certificate: None,
            tvs_id,
            private_key_wrapping_keys: Vec::new(),
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
        if let Some(keys) = metadata.private_key_wrapping_keys {
            self.private_key_wrapping_keys.push(keys.primary);
            self.private_key_wrapping_keys
                .extend_from_slice(&keys.active);
        }
        Ok(())
    }

    async fn fetch_orchestrator_metadata(
        &self,
    ) -> Result<FetchOrchestratorMetadataResponse, String> {
        let response = self
            .inner
            .clone()
            .fetch_orchestrator_metadata(Request::new(()))
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
            self.tvs_id,
        )
        .await
    }

    async fn send_evidence_internal(
        &self,
        evidence: Evidence,
        signing_key: SigningKey,
        tvs_authentication_key: Vec<u8>,
        tee_certificate: Vec<u8>,
        tvs_id: i64,
    ) -> Result<Vec<u8>, String> {
        let mut tvs =
            tvs_trusted_client::TvsClient::new(&tvs_authentication_key, &self.tvs_public_key)?;

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
                let orch_message = ForwardingTvsMessage {
                    tvs_id,
                    opaque_message: Some(handshake_initial.clone()),
                };
                outbound_tx
                    .send(orch_message)
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
                let orch_message = ForwardingTvsMessage {
                    tvs_id,
                    opaque_message: Some(command.clone()),
                };
                outbound_tx
                    .send(orch_message)
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
    use crypto::P256Scalar;
    use futures::FutureExt;
    use key_fetcher::ffi::create_test_key_fetcher_wrapper;
    use oak_proto_rust::oak::attestation::v1::TcbVersion;
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::pin::Pin;
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio_stream::wrappers::TcpListenerStream;
    use tokio_stream::{wrappers::ReceiverStream, StreamExt};
    use tonic::Response;
    use tvs_proto::privacy_sandbox::tvs::{
        stage0_measurement, AmdSev, AppraisalPolicies, AppraisalPolicy, Measurement, Secret,
        Signature as PolicySignature, Stage0Measurement, VerifyReportResponse,
    };

    struct TestLauncherService {
        pub tvs_authentication_key: Vec<u8>,
        pub tvs_service: Arc<trusted_tvs::service::Service>,
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
                private_key_wrapping_keys: None,
            }))
        }

        async fn verify_report(
            &self,
            request: tonic::Request<tonic::Streaming<ForwardingTvsMessage>>,
        ) -> Result<tonic::Response<Self::VerifyReportStream>, tonic::Status> {
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            let tvs_service = Arc::clone(&self.tvs_service);
            let mut stream = request.into_inner();
            tokio::spawn(async move {
                let mut tvs_request_handler =
                    tvs_service.create_request_handler(NOW_UTC_MILLIS, "test_user");
                while let Some(message) = stream.next().await {
                    match message {
                        Ok(message) => {
                            let Ok(report) = tvs_request_handler.verify_report(
                                message.opaque_message.unwrap().binary_message.as_slice(),
                            ) else {
                                let _ = tx
                                    .send(Err(tonic::Status::internal("Error verifying report")))
                                    .await;
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
        let policies = AppraisalPolicies {
            policies: vec![AppraisalPolicy{
                measurement: Some(Measurement {
                    stage0_measurement: Some(Stage0Measurement{
                        r#type: Some(stage0_measurement::Type::AmdSev(AmdSev{
                            sha384: "de654ed1eb03b69567338d357f86735c64fc771676bcd5d05ca6afe86f3eb9f7549222afae6139a8d282a34d09d59f95".to_string(),
                            min_tcb_version: Some(TcbVersion{
                                boot_loader: 7,
                                microcode: 62,
                                snp: 15,
                                tee: 0,
                            }),
                        })),
                    }),
                    kernel_image_sha256: "442a36913e2e299da2b516814483b6acef11b63e03f735610341a8561233f7bf".to_string(),
                    kernel_setup_data_sha256: "68cb426afaa29465f7c71f26d4f9ab5a82c2e1926236648bec226a8194431db9".to_string(),
                    init_ram_fs_sha256: "3b30793d7f3888742ad63f13ebe6a003bc9b7634992c6478a6101f9ef323b5ae".to_string(),
                    memory_map_sha256: "4c985428fdc6101c71cc26ddc313cd8221bcbc54471991ec39b1be026d0e1c28".to_string(),
                    acpi_table_sha256: "a4df9d8a64dcb9a713cec028d70d2b1599faef07ccd0d0e1816931496b4898c8".to_string(),
                    kernel_cmd_line_regex: "^ console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=10000000 brd.max_part=1 ip=10.0.2.15:::255.255.255.0::eth0:off$".to_string(),
                    system_image_sha256: "e3ded9e7cfd953b4ee6373fb8b412a76be102a6edd4e05aa7f8970e20bfc4bcd".to_string(),
                    container_binary_sha256:"bf173d846c64e5caf491de9b5ea2dfac349cfe22a5e6f03ad8048bb80ade430c".to_string(),

                }),
                signature: vec![PolicySignature{
                    signature: "003cfc8524266b283d4381e967680765bbd2a9ac2598eb256ba82ba98b3e23b384e72ad846c4ec3ff7b0791a53011b51d5ec1f61f61195ff083c4a97d383c13c".to_string(),
                    signer: "".to_string(),
                    },
                    ],
            }],
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
        let tvs_private_key = P256Scalar::generate();
        let tvs_authentication_key = P256Scalar::generate();
        let test_service = TestLauncherService {
            tvs_authentication_key: tvs_authentication_key.bytes().to_vec(),
            tvs_service: Arc::new(
                trusted_tvs::service::Service::new(
                    Box::new(key_fetcher::KeyFetcher::new(
                        create_test_key_fetcher_wrapper(
                            /*primary_private_key=*/ &tvs_private_key.bytes(),
                            /*secondary_private_key,*/ &[],
                            /*user_id=*/ 1,
                            /*user_authentication_public_key=*/
                            &tvs_authentication_key.compute_public_key(),
                            /*key_id=*/ 64,
                            /*user_secret=*/ b"test_secret1",
                            /*public_key=*/ b"test_public_key1",
                        ),
                    )),
                    &default_appraisal_policies(),
                    /*enable_policy_signature=*/ true,
                    /*accept_insecure_policies=*/ false,
                )
                .unwrap(),
            ),
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
                0,
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
        assert_eq!(
            response,
            VerifyReportResponse {
                secrets: vec![Secret {
                    key_id: 64,
                    public_key: "test_public_key1".into(),
                    private_key: "test_secret1".into(),
                }],
            }
        );
    }

    #[tokio::test]
    async fn verify_report_unauthenticated_error() {
        let tvs_private_key = P256Scalar::generate();
        let test_service = TestLauncherService {
            tvs_authentication_key: P256Scalar::generate().bytes().to_vec(),
            tvs_service: Arc::new(
                trusted_tvs::service::Service::new(
                    Box::new(key_fetcher::KeyFetcher::new(
                        create_test_key_fetcher_wrapper(
                            /*primary_private_key=*/ &tvs_private_key.bytes(),
                            /*secondary_private_key,*/ &[],
                            /*user_id=*/ 1,
                            /*user_authentication_public_key=*/
                            &P256Scalar::generate().compute_public_key(),
                            /*key_id=*/ 64,
                            /*user_secret=*/ b"test_secret1",
                            /*public_key=*/ b"test_public_key1",
                        ),
                    )),
                    &default_appraisal_policies(),
                    /*enable_policy_signature=*/ true,
                    /*accept_insecure_policies=*/ false,
                )
                .unwrap(),
            ),
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
                0,
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
            Ok(_) => panic!("send_evidence() should fail."),
            Err(e) => assert!(e.contains("Error verifying report")),
        }
    }

    #[tokio::test]
    async fn fetch_tee_certificate_successful() {
        let tvs_private_key = P256Scalar::generate();
        let test_service = TestLauncherService {
            tvs_authentication_key: vec![],
            tvs_service: Arc::new(
                trusted_tvs::service::Service::new(
                    Box::new(key_fetcher::KeyFetcher::new(
                        create_test_key_fetcher_wrapper(
                            /*primary_private_key=*/ &tvs_private_key.bytes(),
                            /*secondary_private_key,*/ &[],
                            /*user_id=*/ 1,
                            /*user_authentication_public_key=*/ &[],
                            /*key_id=*/ 64,
                            /*user_secret=*/ b"test_secret1",
                            /*public_key=*/ b"test_public_key1",
                        ),
                    )),
                    &default_appraisal_policies(),
                    /*enable_policy_signature=*/ true,
                    /*accept_insecure_policies=*/ false,
                )
                .unwrap(),
            ),
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
                0,
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
                private_key_wrapping_keys: None,
            }
        )
    }
}
