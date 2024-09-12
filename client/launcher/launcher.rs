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

use clap::Parser;

#[cxx::bridge(namespace = "privacy_sandbox::launcher")]
mod ffi {
    struct LauncherServerOptions<'a> {
        port: u32,
        // Forwarding TVS options.
        use_tls: bool,
        target: &'a str,
        access_token: &'a str,
        tvs_authentication_key: &'a str,
        private_key_wrapping_keys: &'a [String],
        // Parc server options.
        enable_parc: bool,
        parc_parameters_file: &'a str,
        parc_blobstore_root: &'a str,
    }
    unsafe extern "C++" {
        include!("client/launcher/server-ffi.h");
        type LauncherServerOptions;
        fn CreateAndStartServers(launcher_server_options: &LauncherServerOptions) -> Result<()>;
    }
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "localhost:7779")]
    pub tvs_address: String,
    #[arg(long)]
    pub use_tls: bool,
    #[arg(long, default_value = "")]
    pub access_token: String,
    #[arg(long)]
    pub tvs_authentication_key: String,
    #[arg(long, value_delimiter = ',')]
    pub private_key_wrapping_keys: Vec<String>,
    #[arg(long)]
    pub enable_parc: bool,
    #[arg(long, default_value = "parc_data/parameters/parameters-local.json")]
    pub parc_parameters_file: String,
    #[arg(long, default_value = "parc_data/blob_root")]
    pub parc_blobstore_root: String,
    #[command(flatten)]
    pub oak_args: oak_containers_launcher::Args,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();

    tokio::spawn(async move {
        ffi::CreateAndStartServers(&ffi::LauncherServerOptions {
            port: 8889,
            use_tls: args.use_tls,
            target: &args.tvs_address,
            access_token: &args.access_token,
            tvs_authentication_key: &args.tvs_authentication_key,
            private_key_wrapping_keys: &args.private_key_wrapping_keys,
            enable_parc: args.enable_parc,
            parc_parameters_file: &args.parc_parameters_file,
            parc_blobstore_root: &args.parc_blobstore_root,
        })
    })
    .await?
    .map_err(|error| anyhow::anyhow!("error waiting for launcher: {}", error))?;

    env_logger::init();
    let mut launcher = oak_containers_launcher::Launcher::create(args.oak_args)
        .await
        .map_err(|error| anyhow::anyhow!("couldn't create hats launcher: {}", error))?;
    launcher
        .wait()
        .await
        .map_err(|error| anyhow::anyhow!("error waiting for launcher: {}", error))?;
    Ok(())
}
