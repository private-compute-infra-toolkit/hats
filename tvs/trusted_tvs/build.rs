#[cfg(feature = "bazel")]
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let include_path = "../../submodules/oak";
    // paths differs between Cargo and Bazel.
    #[cfg(feature = "bazel")]
    let include_path =
        &env::var("OAK_PROTO_INCLUDE")?.replace("proto/attestation/evidence.proto", "");
    micro_rpc_build::compile(
        &["../proto/tvs_messages.proto"],
        &["../", include_path],
        micro_rpc_build::CompileOptions {
            extern_paths: vec![micro_rpc_build::ExternPath::new(
                ".oak.attestation.v1",
                "::oak_proto_rust::oak::attestation::v1",
            )],
            ..Default::default()
        },
    );

    Ok(())
}
