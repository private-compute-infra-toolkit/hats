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
            extern_paths: vec![ExternPath::new(
                ".oak.attestation.v1",
                "::oak_proto_rust::oak::attestation::v1",
            )],
            ..Default::default()
        },
    )?;

    Ok(())
}
