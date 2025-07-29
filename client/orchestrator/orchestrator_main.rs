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

use anyhow::{anyhow, Context};
use clap::{Parser, ValueEnum};
#[allow(deprecated)]
use oak_attestation::ApplicationKeysAttester;
use oak_attestation_types::attester::Attester;
use oak_containers_orchestrator::ipc_server::create_services;
use oak_containers_orchestrator::launcher_client::LauncherClient;
use oak_proto_rust::oak::attestation::v1::{endorsements, Endorsements, OakContainersEndorsements};
use prost::Message;
use secret_sharing::SecretSplit;
use std::{fs, path::PathBuf, sync::Arc};
use tokio_util::sync::CancellationToken;
use tvs_grpc_client::TvsClientInterface;

#[derive(Default, Clone, ValueEnum)]
enum SecretShareType {
    #[default]
    NoSplit,
    Shamir,
    Xor,
}

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "http://10.0.2.100:8080")]
    launcher_addr: String,

    #[arg(default_value = "0.0.0.0:4000")]
    orchestrator_addr: String,

    #[arg(long, default_value = "/oak_container")]
    container_dir: PathBuf,

    #[arg(long, default_value = "/oak_utils/orchestrator_ipc")]
    ipc_socket_path: PathBuf,

    #[arg(long, default_value = "oakc")]
    runtime_user: String,

    // For local testing, pass in the path to a file containing the tvs keys in the following format:
    // tvs_id1:tvs_public_key1 (0:1234567890abcde)
    // tvs_id2:tvs_public_key2 (1:abcde1234567890)
    #[arg(long, default_value = "/hats/tvs_public_keys.txt")]
    tvs_public_keys_file: String,

    // Determines type of secret shares for split secret recovery. Valid values are XOR, SHAMIR, or NONE(For single TVS Cases).
    #[arg(long, required = false, value_enum, default_value_t = SecretShareType::default())]
    secret_share_type: SecretShareType,

    // How often to send heart-beats to TVS in seconds.
    #[arg(long, default_value = "3600")]
    tvs_heartbeat_frequency: u64,
}

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    oak_containers_orchestrator::logging::setup()?;

    let args = Args::parse();

    let mut tvs_grpc_clients: Vec<Box<dyn tvs_grpc_client::TvsClientInterface>> = Vec::new();
    let tvs_public_keys =
        fs::read_to_string(args.tvs_public_keys_file).expect("Unable to read file");

    // Here we initialize the tvs grpc clients from the tvs public keys in the system image
    for key in tvs_public_keys.lines() {
        let tvs_id = &key[0..1].parse::<i64>()?;
        let pub_key = &key[2..];
        let tvs: Box<dyn TvsClientInterface> = tvs_grpc_client::TvsGrpcClient::create(
            args.launcher_addr.parse()?,
            hex::decode(pub_key)?,
            *tvs_id,
        )
        .await
        .map_err(|error| anyhow!("couldn't init tvs client: {:?}", error))?;
        tvs_grpc_clients.push(tvs);
    }

    let launcher_client = Arc::new(
        LauncherClient::create(args.launcher_addr.parse()?)
            .await
            .map_err(|error| anyhow!("couldn't create client: {:?}", error))?,
    );

    // Generate application keys.
    let (instance_keys, instance_public_keys) =
        oak_containers_attestation::generate_instance_keys();
    let (group_keys, group_public_keys) = {
        let (group_keys, group_public_keys) = instance_keys.generate_group_keys();
        (Some(Arc::new(group_keys)), Some(group_public_keys))
    };

    // Load application.
    let mut container_bundle = launcher_client
        .get_container_bundle()
        .await
        .map_err(|error| anyhow!("couldn't get container bundle: {:?}", error))?;

    // Create a container event and add it to the event log.
    let mut attester: oak_attestation::dice::DiceAttester =
        oak_containers_orchestrator::dice::load_stage1_dice_data()?;
    let container_event = oak_containers_attestation::create_container_event(
        container_bundle.clone(),
        /*application_config=*/ &[0u8; 0][..],
        &instance_public_keys,
    );
    let encoded_event = container_event.encode_to_vec();
    attester.extend(&encoded_event)?;

    // Add the container event to the DICE chain.
    #[allow(deprecated)]
    let evidence = {
        let container_layer =
            oak_containers_attestation::create_container_dice_layer(&container_event);
        attester.add_application_keys(
            container_layer,
            &instance_public_keys.encryption_public_key,
            &instance_public_keys.signing_public_key,
            if let Some(ref group_public_keys) = group_public_keys {
                Some(&group_public_keys.encryption_public_key)
            } else {
                None
            },
            None,
        )?
    };

    launcher_client
        .send_attestation_evidence(evidence.clone())
        .await
        .map_err(|error| anyhow!("couldn't send attestation evidence: {:?}", error))?;

    if let Some(path) = args.ipc_socket_path.parent() {
        tokio::fs::create_dir_all(path).await?;
    }
    let endorsements = Endorsements {
        r#type: Some(endorsements::Type::OakContainers(
            OakContainersEndorsements {
                root_layer: None,
                kernel_layer: None,
                system_layer: None,
                container_layer: None,
            },
        )),
        events: vec![],
        initial: None,
        platform: None,
    };
    let signing_key_clone = instance_keys.signing_key.clone();
    let (oak_orchestrator_server, oak_crypto_server) = create_services(
        evidence.clone(),
        endorsements,
        instance_keys,
        group_keys
            .clone()
            .context("group keys were not provisioned")?,
        /*application_config=*/ vec![],
        launcher_client,
    );
    let num_tvs_clients = tvs_grpc_clients.len();
    let secret_split: Option<Box<dyn SecretSplit>> = match args.secret_share_type {
        SecretShareType::Shamir => Some(Box::new(
            secret_sharing::shamir_sharing::ShamirSharing::new(
                num_tvs_clients,
                num_tvs_clients - 1,
                secret_sharing::shamir_sharing::get_prime(),
            )
            .map_err(|error| {
                anyhow::anyhow!("couldn't create shamir sharing object: {:?}", error)
            })?,
        )),
        SecretShareType::Xor => Some(Box::new(
            secret_sharing::xor_sharing::XorSharing::new(num_tvs_clients).map_err(|error| {
                anyhow::anyhow!("couldn't create xor sharing object: {:?}", error)
            })?,
        )),
        SecretShareType::NoSplit => {
            if num_tvs_clients != 1 {
                anyhow::bail!("expected one TVS endpoint, got {num_tvs_clients}");
            }
            None
        }
    };

    let tvs_secret_manager = tvs_secret_manager::TvsSecretManager::create(
        tvs_grpc_clients,
        &evidence.clone(),
        signing_key_clone,
        secret_split,
        args.tvs_heartbeat_frequency,
    )
    .await?;
    let hats_server = hats_server::HatsServer::new(tvs_secret_manager);

    // Start application and gRPC servers.
    let user = nix::unistd::User::from_name(&args.runtime_user)
        .context(format!("error resolving user {}", args.runtime_user))?
        .context(format!("user `{}` not found", args.runtime_user))?;
    let cancellation_token = CancellationToken::new();
    tokio::try_join!(
        oak_containers_orchestrator::key_provisioning::create(
            &args.orchestrator_addr,
            group_keys
                .clone()
                .context("group keys were not provisioned")?,
            cancellation_token.clone(),
        ),
        oak_containers_orchestrator::container_runtime::run(
            &mut container_bundle,
            &args.container_dir,
            user.uid,
            user.gid,
            &args.ipc_socket_path,
            cancellation_token.clone(),
        ),
        hats_server::create_services(
            &args.ipc_socket_path,
            oak_orchestrator_server,
            oak_crypto_server,
            hats_server,
            cancellation_token
        ),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use client_proto::privacy_sandbox::server_common::hats_orchestrator_server::HatsOrchestrator;
    use client_proto::privacy_sandbox::tvs::{Secret, VerifyReportResponse};
    use hats_server::HatsServer;
    use mockall::predicate::*;
    use oak_containers_attestation::generate_instance_keys;
    use prost::Message;
    use tvs_grpc_client::MockTvsClientInterface;

    #[tokio::test]
    async fn test_hats_server_with_mocked_tvs_client() {
        // Create a mock TVS client
        let mut mock_tvs_client = MockTvsClientInterface::new();
        let private_key = vec![1, 2, 3];
        mock_tvs_client
            .expect_send_evidence()
            .with(always(), always())
            .returning(move |_, _| {
                let response = VerifyReportResponse {
                    secrets: vec![Secret {
                        key_id: "501".to_string(),
                        public_key: "test-public-key1".to_string(),
                        private_key: private_key.clone(),
                    }],
                };
                let mut encoded = Vec::new();
                VerifyReportResponse::encode(&response, &mut encoded).unwrap();
                Ok(encoded)
            });
        let mock_tvs_client_box = Box::new(mock_tvs_client) as Box<dyn TvsClientInterface>;
        let tvs_grpc_clients: Vec<Box<dyn tvs_grpc_client::TvsClientInterface>> =
            vec![mock_tvs_client_box];

        // Generate instance keys
        let (instance_keys, _) = generate_instance_keys();

        // Create a TvsSecretManager
        let secret_split: Option<Box<dyn SecretSplit>> = None;
        let tvs_secret_manager = tvs_secret_manager::TvsSecretManager::create(
            tvs_grpc_clients,
            &oak_proto_rust::oak::attestation::v1::Evidence::default(),
            instance_keys.signing_key.clone(),
            secret_split,
            3600,
        )
        .await
        .unwrap();

        // Create a HatsServer
        let hats_server = HatsServer::new(tvs_secret_manager);

        // Test get_keys
        let request = tonic::Request::new(());
        let response = hats_server.get_keys(request).await.unwrap();
        let keys = response.into_inner().keys;
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_id, "501".to_string());
        assert_eq!(keys[0].public_key, "test-public-key1");
        assert_eq!(keys[0].private_key, vec![1, 2, 3]);
    }
}
