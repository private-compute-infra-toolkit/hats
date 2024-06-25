use anyhow::{anyhow, Context};
use clap::Parser;
use oak_containers_orchestrator::{
    crypto::generate_instance_keys, launcher_client::LauncherClient,
    proto::oak::containers::v1::KeyProvisioningRole,
};
use std::{path::PathBuf, sync::Arc};
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

    #[arg(long, default_value = "", required = true)]
    tvs_public_key: String,

    #[arg(default_value = "http://10.0.2.100:8889")]
    hats_launcher_addr: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    oak_containers_orchestrator::logging::setup()?;

    let args = Args::parse();
    let client = tvs_grpc_client::TvsGrpcClient::create(
        args.hats_launcher_addr.parse()?,
        args.tvs_public_key,
    )
    .await
    .map_err(|error| anyhow!("couldn't get tvs client: {:?}", error))?;

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

    let token = client
        .send_evidence(evidence, instance_keys.signing_key.clone())
        .await
        .map_err(|error| anyhow!("XXX couldn't get tvs client: {:?}", error))?;
    // Print the token for now.
    println!("token {token}");

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
        oak_containers_orchestrator::ipc_server::create(
            &args.ipc_socket_path,
            instance_keys,
            group_keys
                .clone()
                .context("group keys were not provisioned")?,
            application_config,
            launcher_client,
            cancellation_token.clone(),
        ),
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
            cancellation_token,
        ),
    )?;

    Ok(())
}
