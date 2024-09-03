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
use oak_containers_orchestrator::{
    crypto::generate_instance_keys, launcher_client::LauncherClient,
};
use oak_proto_rust::oak::containers::v1::KeyProvisioningRole;
use std::{collections::HashMap, fs, path::PathBuf, sync::Arc};
use tokio_util::sync::CancellationToken;

#[derive(Parser, Debug)]
struct Args {
    #[arg(default_value = "http://10.0.2.100:8080")]
    launcher_addr: String,

    #[arg(default_value = "10.0.2.15:4000")]
    orchestrator_addr: String,

    #[arg(long, default_value = "/oak_container")]
    container_dir: PathBuf,

    #[arg(long, default_value = "/oak_utils/orchestrator_ipc")]
    ipc_socket_path: PathBuf,

    #[arg(long, default_value = "oakc")]
    runtime_user: String,

    #[arg(long, default_value = "")]
    tvs_public_key: String,

    #[arg(default_value = "http://10.0.2.100:8889")]
    hats_launcher_addr: String,

    // For local testing, pass in the path to a file containing the tvs keys in the following format:
    // tvs_id1:tvs_public_key1 (0:1234567890abcde)
    // tvs_id2:tvs_public_key2 (1:abcde1234567890)
    #[arg(long, default_value = "/hats/tvs_public_keys")]
    tvs_public_keys_file: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    oak_containers_orchestrator::logging::setup()?;

    let args = Args::parse();

    let mut grpc_client_map: HashMap<i64, tvs_grpc_client::TvsGrpcClient> = HashMap::new();
    println!("{}", args.tvs_public_keys_file);
    let tvs_public_keys =
        fs::read_to_string(args.tvs_public_keys_file).expect("Unable to read file");
    for key in tvs_public_keys.lines() {
        let tvs_orch_identifier = &key[0..1];
        let pub_key = &key[2..];
        let tvs: tvs_grpc_client::TvsGrpcClient = tvs_grpc_client::TvsGrpcClient::create(
            args.hats_launcher_addr.parse()?,
            hex::decode(pub_key)?,
        )
        .await
        .map_err(|error| anyhow!("couldn't get tvs client: {:?}", error))?;
        grpc_client_map.insert(tvs_orch_identifier.parse::<i64>()?, tvs);
    }

    let launcher_client = Arc::new(
        LauncherClient::create(args.launcher_addr.parse()?)
            .await
            .map_err(|error| anyhow!("couldn't create client: {:?}", error))?,
    );

    // Get key provisioning role.
    let key_provisioning_role = launcher_client
        .get_key_provisioning_role()
        .await
        .map_err(|error| anyhow!("couldn't get key provisioning role: {:?}", error))?;

    // Generate application keys.
    let (instance_keys, instance_public_keys) = generate_instance_keys();
    let (mut group_keys, group_public_keys) =
        if key_provisioning_role == KeyProvisioningRole::Leader {
            let (group_keys, group_public_keys) = instance_keys.generate_group_keys();
            (Some(Arc::new(group_keys)), Some(group_public_keys))
        } else {
            (None, None)
        };

    // Load application.
    let container_bundle = launcher_client
        .get_container_bundle()
        .await
        .map_err(|error| anyhow!("couldn't get container bundle: {:?}", error))?;
    let application_config = launcher_client
        .get_application_config()
        .await
        .map_err(|error| anyhow!("couldn't get application config: {:?}", error))?;

    // Generate attestation evidence and send it to the Hostlib.
    let dice_builder = oak_containers_orchestrator::dice::load_stage1_dice_data()?;
    let additional_claims = oak_containers_orchestrator::dice::measure_container_and_config(
        &container_bundle,
        &application_config,
    );
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

    let token = grpc_client_map[&0]
        .send_evidence(evidence, instance_keys.signing_key.clone())
        .await
        .map_err(|error| anyhow!("couldn't get tvs client: {:?}", error))?;

    // Request group keys.
    if key_provisioning_role == KeyProvisioningRole::Follower {
        let get_group_keys_response = launcher_client
            .get_group_keys()
            .await
            .map_err(|error| anyhow!("couldn't get group keys: {:?}", error))?;
        let provisioned_group_keys = instance_keys
            .provide_group_keys(get_group_keys_response)
            .context("couldn't provide group keys")?;
        group_keys = Some(Arc::new(provisioned_group_keys));
    }

    if let Some(path) = args.ipc_socket_path.parent() {
        tokio::fs::create_dir_all(path).await?;
    }

    // Start application and gRPC servers.
    let user = nix::unistd::User::from_name(&args.runtime_user)
        .context(format!("error resolving user {}", args.runtime_user))?
        .context(format!("user `{}` not found", args.runtime_user))?;
    let cancellation_token = CancellationToken::new();
    tokio::try_join!(
        oak_containers_orchestrator::key_provisioning::create(
            &args.orchestrator_addr,
            group_keys.context("group keys were not provisioned")?,
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
        // this is the old launcher
        hats_server::create(&args.ipc_socket_path, &token, cancellation_token),
    )?;
    Ok(())
}
