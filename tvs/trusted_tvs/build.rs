fn main() {
    micro_rpc_build::compile(
        &["../proto/tvs.proto"],
        &[".", "../"],
        micro_rpc_build::CompileOptions::default(),
    );
}
