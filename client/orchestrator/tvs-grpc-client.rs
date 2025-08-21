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
use client_proto::pcit::client::{
    launcher_service_client, FetchOrchestratorMetadataResponse, ForwardingTvsMessage,
};
use client_proto::pcit::tvs::OpaqueMessage;
use hyper_util::rt::TokioIo;
use mockall::automock;
use oak_proto_rust::oak::attestation::v1::Evidence;
use p256::ecdsa::SigningKey;
use prost::Message;
use tokio_vsock::{VsockAddr, VsockStream};
use tonic::transport::Channel;
use tonic::Request;
use tower::service_fn;

#[automock]
#[tonic::async_trait]
pub trait TvsClientInterface: Send + Sync {
    async fn send_evidence(
        &self,
        evidence: Evidence,
        signing_key: SigningKey,
    ) -> Result<Vec<u8>, String>;

    async fn fetch_orchestrator_metadata(
        &self,
    ) -> Result<FetchOrchestratorMetadataResponse, String>;
}

#[tonic::async_trait]
impl TvsClientInterface for TvsGrpcClient {
    async fn send_evidence(
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

    async fn fetch_orchestrator_metadata(
        &self,
    ) -> Result<FetchOrchestratorMetadataResponse, String> {
        TvsGrpcClient::fetch_orchestrator_metadata_internal(self)
            .await
            .map_err(|error| format!("couldn't find tee metadata: {:?}", error))
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
    ) -> Result<Box<dyn TvsClientInterface>, Box<dyn std::error::Error>> {
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
                    .next_back()
                    .context("failed to extract port from vsock address")?
                    .parse::<u32>()
                    .context("invalid vsock port")?,
            );
            // Channel builder does not handle non-TCP URIs very well.
            // When passing vSock or UDS URI it creates a TCP channel.
            // Here we pass a fake URI schema so that it fails and falls
            // back to connect_with_connector where we create a vSock stream.
            // https://github.com/hyperium/tonic/issues/608
            let connector = service_fn(move |_| async move {
                Ok::<_, std::io::Error>(TokioIo::new(VsockStream::connect(vsock_addr).await?))
            });
            Channel::builder(tonic::transport::Uri::from_static("http://0:0"))
                .connect_with_connector(connector)
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
    ) -> Result<Box<dyn TvsClientInterface>, Box<dyn std::error::Error>> {
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
        Ok(Box::new(tvs_grp_client))
    }

    // Get metadata from the launcher.
    async fn init(&mut self) -> Result<(), String> {
        let metadata = TvsGrpcClient::fetch_orchestrator_metadata_internal(self).await?;
        self.tee_certificate = Some(metadata.tee_certificate);
        self.tvs_authentication_key = Some(metadata.tvs_authentication_key);
        if let Some(keys) = metadata.private_key_wrapping_keys {
            self.private_key_wrapping_keys.push(keys.primary);
            self.private_key_wrapping_keys
                .extend_from_slice(&keys.active);
        }
        Ok(())
    }

    async fn fetch_orchestrator_metadata_internal(
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
    use client_proto::pcit::client::launcher_service_server::{
        LauncherService, LauncherServiceServer,
    };
    use crypto::P256Scalar;
    use futures::FutureExt;
    use key_fetcher::ffi::create_test_key_fetcher_wrapper;
    use oak_proto_rust::oak::attestation::v1::TcbVersion;
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::pin::Pin;
    use std::sync::Arc;
    #[cfg(feature = "dynamic_attestation")]
    use test_utils_rs::create_dynamic_genoa_policy;
    use tokio::net::TcpListener;
    use tokio_stream::wrappers::TcpListenerStream;
    use tokio_stream::{wrappers::ReceiverStream, StreamExt};
    use tonic::Response;
    use tvs_proto::pcit::tvs::{
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

    fn get_evidence_v1_genoa() -> oak_proto_rust::oak::attestation::v1::Evidence {
        oak_proto_rust::oak::attestation::v1::Evidence::decode(
            include_bytes!("../../tvs/test_data/evidence_v1_genoa.binarypb").as_slice(),
        )
        .expect("could not decode evidence")
    }

    const NOW_UTC_MILLIS: i64 = 1698829200000;

    #[tokio::test]
    async fn verify_report_successful() {
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
        let tvs_authentication_key = P256Scalar::generate();
        let test_service = TestLauncherService {
            tvs_authentication_key: tvs_authentication_key.bytes().to_vec(),
            tvs_service: Arc::new(
                trusted_tvs::service::Service::new(
                    Arc::new(key_fetcher::KeyFetcher::new(
                        create_test_key_fetcher_wrapper(
                            /*primary_private_key=*/ &tvs_private_key.bytes(),
                            /*secondary_private_key,*/ &[],
                            /*user_id=*/ b"1",
                            /*user_authentication_public_key=*/
                            &tvs_authentication_key.compute_public_key(),
                            /*key_id=*/ b"64",
                            /*user_secret=*/ b"test_secret1",
                            /*public_key=*/ b"test_public_key1",
                        ),
                    )),
                    &policies,
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
                    get_evidence_v1_genoa(),
                    SigningKey::from_slice(
                        &hex::decode(
                            "be828103ab28b93a5d91592d69374541d6e7decd287ef7df1f990a87f231cb8c",
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
                    key_id: "64".into(),
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
                    Arc::new(key_fetcher::KeyFetcher::new(
                        create_test_key_fetcher_wrapper(
                            /*primary_private_key=*/ &tvs_private_key.bytes(),
                            /*secondary_private_key,*/ &[],
                            /*user_id=*/ b"1",
                            /*user_authentication_public_key=*/
                            &P256Scalar::generate().compute_public_key(),
                            /*key_id=*/ b"64",
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
                    get_evidence_v1_genoa(),
                    SigningKey::from_slice(
                        &hex::decode(
                            "be828103ab28b93a5d91592d69374541d6e7decd287ef7df1f990a87f231cb8c",
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
                    Arc::new(key_fetcher::KeyFetcher::new(
                        create_test_key_fetcher_wrapper(
                            /*primary_private_key=*/ &tvs_private_key.bytes(),
                            /*secondary_private_key,*/ &[],
                            /*user_id=*/ b"1",
                            /*user_authentication_public_key=*/ &[],
                            /*key_id=*/ b"64",
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
            .expect("couldn't create tvs client");
            tvs_client.fetch_orchestrator_metadata().await
        })
        .await;

        let _ = shutdown_tx.send(());
        let _ = server.await;
        let want = include_bytes!("../../tvs/test_data/vcek_genoa.crt").to_vec();
        assert_eq!(
            cert.unwrap().unwrap(),
            FetchOrchestratorMetadataResponse {
                tee_certificate: want,
                tvs_authentication_key: vec![],
                private_key_wrapping_keys: None,
            }
        )
    }
}
