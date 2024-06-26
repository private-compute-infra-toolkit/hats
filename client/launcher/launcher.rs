use clap::Parser;

#[cxx::bridge(namespace = "privacy_sandbox::tvs")]
mod ffi {
    unsafe extern "C++" {
        include!("client/launcher/forwarding-tvs-server-ffi.h");
        fn CreateAndStartForwardingTvsServer(
            port: u32,
            use_tls: bool,
            target: &str,
            access_token: &str,
        ) -> Result<()>;
    }
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, required = true, default_value = "localhost:7779")]
    pub tvs_address: String,
    #[arg(long)]
    pub use_tls: bool,
    #[arg(long, default_value = "")]
    pub access_token: String,
    #[command(flatten)]
    pub oak_args: oak_containers_launcher::Args,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();
    tokio::spawn(async move {
        ffi::CreateAndStartForwardingTvsServer(
            8889,
            args.use_tls,
            &args.tvs_address,
            &args.access_token,
        )
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
