use clap::Parser;
use oak_containers_launcher::path_exists;

#[cxx::bridge(namespace = "privacy_sandbox::tvs")]
mod ffi {
    unsafe extern "C++" {
        include!("client/launcher/forwarding-tvs-server-ffi.h");
        fn CreateAndStartForwardingTvsServer(port: u32, target: &str, use_tls: bool);
    }
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, required = true, default_value = "localhost:7779")]
    pub tvs_address: String,
    #[arg(long)]
    pub use_tls: bool,
    #[command(flatten)]
    pub oak_args: oak_containers_launcher::Args,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();
    tokio::spawn(async move {
        ffi::CreateAndStartForwardingTvsServer(8889, &args.tvs_address, args.use_tls)
    });
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
