fn main() -> Result<(), Box<dyn std::error::Error>> {
    micro_rpc_build::compile(
        &["../proto/tvs_messages.proto"],
        &["../"],
        Default::default(),
    );

    Ok(())
}
