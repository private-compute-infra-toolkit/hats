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
use clap::Parser;
use hats_server::proto::privacy_sandbox::tvs::{Secret, VerifyReportResponse};
use oak_containers_orchestrator::ipc_server::create_services;
use oak_containers_orchestrator::launcher_client::LauncherClient;
use oak_proto_rust::oak::attestation::v1::{endorsements, Endorsements, OakContainersEndorsements};
use prost::Message;
use std::{collections::HashMap, fs, path::PathBuf, sync::Arc};
use tokio_util::sync::CancellationToken;

#[derive(Parser, Debug)]
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

    #[arg(long, default_value = "")]
    tvs_public_key: String,

    // For local testing, pass in the path to a file containing the tvs keys in the following format:
    // tvs_id1:tvs_public_key1 (0:1234567890abcde)
    // tvs_id2:tvs_public_key2 (1:abcde1234567890)
    #[arg(long, default_value = "/hats/tvs_public_keys.txt")]
    tvs_public_keys_file: String,
}

struct KeyShares {
    public_key: String,
    shares: Vec<secret_sharing::Share>,
}

pub fn recover_secrets(response_vec: &Vec<VerifyReportResponse>) -> Result<Vec<u8>, anyhow::Error> {
    let mut recovered_secrets: Vec<Secret> = Vec::new();
    // this maps key_id to (public key, private key shares)
    let mut share_map: HashMap<i64, KeyShares> = HashMap::new();
    for response in response_vec {
        for secret in &response.secrets {
            let share = secret_sharing::desearialize_share(&secret.private_key)
                .map_err(|e| anyhow!("Invalid key({:?}) stored:{:?}", secret.key_id, e))?;
            let key_shares = share_map.entry(secret.key_id).or_insert(KeyShares {
                public_key: (*secret.public_key).to_string(),
                shares: vec![],
            });
            key_shares.shares.push(share);
        }
    }
    for (key_id, key_shares) in share_map {
        // we set the threshold to be 1 less than number of shares
        let numshares = key_shares.shares.len();
        let sham = secret_sharing::SecretSharing {
            numshares,
            prime: secret_sharing::get_prime(),
            threshold: numshares - 1,
        };
        recovered_secrets.push(Secret {
            key_id,
            public_key: (*key_shares.public_key).to_string(),
            private_key: sham
                .recover(&key_shares.shares)
                .map_err(|err| anyhow::anyhow!("Failed to recover the secret: {err:?}"))?,
        });
    }
    let recovered_report = VerifyReportResponse {
        secrets: recovered_secrets,
    };
    let mut encoded_report: Vec<u8> = Vec::new();
    VerifyReportResponse::encode(&recovered_report, &mut encoded_report)?;
    Ok(encoded_report)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    oak_containers_orchestrator::logging::setup()?;

    let args = Args::parse();

    let mut tvs_grpc_clients: Vec<tvs_grpc_client::TvsGrpcClient> = Vec::new();
    let tvs_public_keys =
        fs::read_to_string(args.tvs_public_keys_file).expect("Unable to read file");

    // Here we initialize the tvs grpc clients from the tvs public keys in the system image
    for key in tvs_public_keys.lines() {
        let tvs_id = &key[0..1].parse::<i64>()?;
        let pub_key = &key[2..];
        let tvs: tvs_grpc_client::TvsGrpcClient = tvs_grpc_client::TvsGrpcClient::create(
            args.launcher_addr.parse()?,
            hex::decode(pub_key)?,
            *tvs_id,
        )
        .await
        .map_err(|error| anyhow!("couldn't get tvs client: {:?}", error))?;
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
    let container_bundle = launcher_client
        .get_container_bundle()
        .await
        .map_err(|error| anyhow!("couldn't get container bundle: {:?}", error))?;

    // Generate attestation evidence and send it to the Hostlib.
    let dice_builder = oak_containers_orchestrator::dice::load_stage1_dice_data()?;
    let additional_claims =
        oak_containers_attestation::measure_container_and_config(&container_bundle, &[]);
    let evidence = dice_builder.add_application_keys(
        additional_claims,
        &instance_public_keys.encryption_public_key,
        &instance_public_keys.signing_public_key,
        if let Some(ref group_public_keys) = group_public_keys {
            Some(&group_public_keys.encryption_public_key)
        } else {
            None
        },
        None,
    )?;

    launcher_client
        .send_attestation_evidence(evidence.clone())
        .await
        .map_err(|error| anyhow!("couldn't send attestation evidence: {:?}", error))?;

    if let Some(path) = args.ipc_socket_path.parent() {
        tokio::fs::create_dir_all(path).await?;
    }

    let encoded_report: Vec<u8>;
    if tvs_grpc_clients.len() > 1 {
        let mut response_vec: Vec<VerifyReportResponse> = Vec::new();
        for tvs_grpc_client in tvs_grpc_clients {
            response_vec.push(VerifyReportResponse::decode(
                tvs_grpc_client
                    .send_evidence(evidence.clone(), instance_keys.signing_key.clone())
                    .await
                    .map_err(|error| anyhow!("couldn't get tvs client: {:?}", error))?
                    .as_slice(),
            )?);
        }
        encoded_report = recover_secrets(&response_vec)?;
    } else {
        encoded_report = tvs_grpc_clients[0]
            .send_evidence(evidence.clone(), instance_keys.signing_key.clone())
            .await
            .map_err(|error| anyhow!("couldn't get tvs client: {:?}", error))?
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
        event_endorsements: None,
    };
    let (oak_orchestrator_server, oak_crypto_server) = create_services(
        evidence,
        endorsements,
        instance_keys,
        group_keys
            .clone()
            .context("group keys were not provisioned")?,
        /*application_config=*/ vec![],
        launcher_client,
    );

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
            &container_bundle,
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
            &encoded_report,
            cancellation_token
        ),
    )?;
    Ok(())
}
