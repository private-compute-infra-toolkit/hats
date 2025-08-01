# Copyright 2024 Google LLC.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#      https://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

workspace(name = "hats")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_file")
load("@rules_rust//rust:repositories.bzl", "rules_rust_dependencies", "rust_register_toolchains", "rust_repository_set")

rules_rust_dependencies()

RUST_EDITION = "2021"

RUST_VERSIONS = [
    "nightly/2025-03-01",
]

rust_register_toolchains(
    edition = RUST_EDITION,
    versions = RUST_VERSIONS,
)

rust_repository_set(
    name = "rust_toolchain_repo",
    edition = RUST_EDITION,
    exec_triple = "x86_64-unknown-linux-gnu",
    extra_rustc_flags = {
        "x86_64-unknown-none": [
            "-Crelocation-model=static",
            "-Ctarget-feature=+sse,+sse2,+ssse3,+sse4.1,+sse4.2,+avx,+avx2,+rdrand,-soft-float",
            "-Ctarget-cpu=x86-64-v3",
            "-Clink-arg=-zmax-page-size=0x200000",
        ],
    },
    extra_target_triples = {
        "x86_64-unknown-none": [
            "@platforms//cpu:x86_64",
            "@platforms//os:none",
        ],
    },
    versions = RUST_VERSIONS,
)

load("@rules_rust//tools/rust_analyzer:deps.bzl", "rust_analyzer_dependencies")

rust_analyzer_dependencies()

# Java gRPC support -- required by oak.
# https://github.com/grpc/grpc-java
http_archive(
    name = "io_grpc_grpc_java",
    sha256 = "4af5ecbaed16455fcda9fdab36e131696f5092858dd130f026069fcf11817a21",
    strip_prefix = "grpc-java-1.56.0",
    urls = [
        # Java gRPC v1.56.0 (2023-06-21).
        "https://github.com/grpc/grpc-java/archive/refs/tags/v1.56.0.tar.gz",
    ],
)

http_archive(
    name = "oak",
    sha256 = "a144f19619a8a2356852d6ba7c55c357e59b2fb0986fbeb782fa401a36b4d00d",
    strip_prefix = "oak-d6f890b76203f55446f46edb51b8690eca3adb4c",
    url = "https://github.com/project-oak/oak/archive/d6f890b76203f55446f46edb51b8690eca3adb4c.tar.gz",
)

load("@oak//bazel/llvm:deps.bzl", "load_llvm_repositories")

load_llvm_repositories()

load("@oak//bazel/llvm:defs.bzl", "setup_llvm_toolchains")

setup_llvm_toolchains()

load("@oak//bazel/llvm:reg.bzl", "register_llvm_toolchains")

register_llvm_toolchains()

load("@oak//bazel/crates:patched_crates.bzl", "load_patched_crates")

load_patched_crates()

load("@oak//bazel/rust:defs.bzl", "setup_rust_dependencies")

setup_rust_dependencies()

load("@oak//bazel/crates:repositories.bzl", "create_oak_crate_repositories")

create_oak_crate_repositories()

load("@oak//bazel/crates:crates.bzl", "load_oak_crate_repositories")

load_oak_crate_repositories()

local_repository(
    name = "enclave",
    path = "third_party/enclave",
)

http_archive(
    name = "google_cloud_cpp",
    sha256 = "9a6e182fd658ba114512cf21bd9f274a315830638f62f0b831113df9e674bea0",
    strip_prefix = "google-cloud-cpp-2.36.0",
    url = "https://github.com/googleapis/google-cloud-cpp/archive/v2.36.0.tar.gz",
)

load("@google_cloud_cpp//bazel:google_cloud_cpp_deps.bzl", "google_cloud_cpp_deps")

google_cloud_cpp_deps()

load("@com_google_googleapis//:repository_rules.bzl", "switched_rules_by_language")

switched_rules_by_language(
    name = "com_google_googleapis_imports",
    cc = True,
    grpc = True,
)

# Bazel rules for building OCI images and runtime bundles.
http_archive(
    name = "rules_oci",
    sha256 = "56d5499025d67a6b86b2e6ebae5232c72104ae682b5a21287770bd3bf0661abf",
    strip_prefix = "rules_oci-1.7.5",
    url = "https://github.com/bazel-contrib/rules_oci/releases/download/v1.7.5/rules_oci-v1.7.5.tar.gz",
)

load("@rules_oci//oci:dependencies.bzl", "rules_oci_dependencies")

rules_oci_dependencies()

load("@rules_oci//oci:repositories.bzl", "LATEST_CRANE_VERSION", "LATEST_ZOT_VERSION", "oci_register_toolchains")

oci_register_toolchains(
    name = "oci",
    crane_version = LATEST_CRANE_VERSION,
    zot_version = LATEST_ZOT_VERSION,
)

load("@rules_oci//oci:pull.bzl", "oci_pull")

oci_pull(
    name = "distroless_cc_debian12",
    digest = "sha256:6714977f9f02632c31377650c15d89a7efaebf43bab0f37c712c30fc01edb973",
    image = "gcr.io/distroless/cc-debian12",
    platforms = ["linux/amd64"],
)

http_file(
    name = "oak_containers_system_image_base",
    downloaded_file_path = "base-image.tar.xz",
    sha256 = "b826bc141a91ae385f9c45a43eb800f691eca92dc537f0dc5d743c51df459ecb",
    url = "https://storage.googleapis.com/oak-bins/base-image/b826bc141a91ae385f9c45a43eb800f691eca92dc537f0dc5d743c51df459ecb.tar.xz",
)

load("@oak//bazel:repositories.bzl", "oak_toolchain_repositories")

oak_toolchain_repositories()

# Declare submodules as local repository so that `build //...` doesn't try to build them.
local_repository(
    name = "submodule2",
    path = "submodules/oak",
)

http_file(
    name = "psp-sev",
    downloaded_file_path = "psp-sev.h",
    sha256 = "bf5128577e19b2e95186a78d6f7e10eb5b1389919c94b0fd5224749e275afe0d",
    url = "https://raw.githubusercontent.com/torvalds/linux/3ec3f5fc4a91e389ea56b111a73d97ffc94f19c6/include/uapi/linux/psp-sev.h",
)

local_repository(
    name = "cxx.rs",
    path = "third_party/cxx.rs",
)

# sev-snp-utils repository and crates repository.

local_repository(
    name = "sev-snp-utils",
    path = "third_party/sev-snp-utils",
)
