use oak_grpc_utils::ExternPath;
use oak_grpc_utils::{generate_grpc_code, CodegenOptions};
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let include_path =
        &env::var("OAK_PROTO_INCLUDE")?.replace("proto/attestation/evidence.proto", "");
    generate_grpc_code(
        &["../../tvs/proto/tvs.proto"],
        &["../..", include_path],
        CodegenOptions {
            build_client: true,
            build_server: true,
            extern_paths: vec![ExternPath::new(
                ".oak.attestation.v1",
                "::oak_proto_rust::oak::attestation::v1",
            )],
            ..Default::default()
        },
    )?;

    Ok(())
}
