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

load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_file")
load("//builders/bazel:deps.bzl", "python_deps")

python_deps()

load("@rules_python//python:repositories.bzl", "py_repositories")

py_repositories()

load("@rules_rust//rust:repositories.bzl", "rules_rust_dependencies", "rust_register_toolchains", "rust_repository_set")

rules_rust_dependencies()

RUST_EDITION = "2021"

RUST_VERSIONS = [
    "1.76.0",
    "nightly/2024-09-01",
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

load("@rules_rust//proto/prost/private:repositories.bzl", "rust_prost_dependencies", "rust_prost_register_toolchains")

rust_prost_dependencies()

rust_prost_register_toolchains()

load("@rules_rust//proto/prost:transitive_repositories.bzl", "rust_prost_transitive_repositories")

rust_prost_transitive_repositories()

load("@rules_rust//proto/protobuf:repositories.bzl", "rust_proto_protobuf_dependencies", "rust_proto_protobuf_register_toolchains")

rust_proto_protobuf_dependencies()

rust_proto_protobuf_register_toolchains()

load("@rules_rust//proto/protobuf:transitive_repositories.bzl", "rust_proto_protobuf_transitive_repositories")

rust_proto_protobuf_transitive_repositories()

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

load("@rules_rust//crate_universe:repositories.bzl", "crate_universe_dependencies")

crate_universe_dependencies(bootstrap = True)

load("@rules_rust//crate_universe:defs.bzl", "crate", "crates_repository")

# Stash packages used by rust code in a repository.
crates_repository(
    name = "hats_crate_index",
    cargo_lockfile = "//:Cargo.bazel.lock",
    lockfile = "//:cargo-bazel-lock.json",
    packages = {
        "hex": crate.spec(version = "*"),
        "hpke": crate.spec(version = "*"),
        "num-bigint": crate.spec(
            features = [
                "rand",
                "serde",
            ],
            version = "*",
        ),
        "p256": crate.spec(version = "*"),
        "prost": crate.spec(
            default_features = False,
            features = ["prost-derive"],
            version = "*",
        ),
        "rand": crate.spec(version = "*"),
        "rand_core": crate.spec(version = "*"),
        "serde": crate.spec(
            default_features = False,
            features = ["derive"],
            version = "*",
        ),
        "serde_json": crate.spec(version = "*"),
        "thiserror": crate.spec(
            version = "*",
        ),
    },
)

load("@hats_crate_index//:defs.bzl", hats_crate_repositories = "crate_repositories")

hats_crate_repositories()

http_archive(
    name = "oak",
    sha256 = "4e2a153133fa137dcd15eb83b12519e67c5f7ee525498c7b59bbbc44132e1de6",
    strip_prefix = "oak-9ca339c91f6ea8ad5d01cbf738620537dab643d5",
    url = "https://github.com/project-oak/oak/archive/9ca339c91f6ea8ad5d01cbf738620537dab643d5.tar.gz",
)

load("@oak//bazel/crates:repositories.bzl", "create_oak_crate_repositories")

create_oak_crate_repositories(
    cargo_lockfile = "//:Cargo_oak.bazel.lock",
    lockfile = "//:cargo-oak-bazel-lock.json",
    no_std_cargo_lockfile = "//:Cargo_oak_no_std.bazel.lock",
    no_std_lockfile = "//:cargo-oak-no-std-bazel-lock.json",
    no_std_no_avx_cargo_lockfile = "//:Cargo_oak_no_std_no_avx-test.bazel.lock",
    no_std_no_avx_lockfile = "//:cargo-oak-no-std-no-avx-test-bazel-lock.json",
)

load("@oak//bazel/crates:crates.bzl", "load_oak_crate_repositories")

load_oak_crate_repositories()

local_repository(
    name = "enclave",
    path = "third_party/enclave",
)

crates_repository(
    name = "enclave_crate_index",
    cargo_lockfile = "//:Cargo.enclave-bazel.lock",
    lockfile = "//:cargo-enclave-bazel-lock.json",
    packages = {
        "static_assertions": crate.spec(version = "*"),
    },
)

load("@enclave_crate_index//:defs.bzl", enclave_crate_repositories = "crate_repositories")

enclave_crate_repositories()

http_archive(
    name = "google_cloud_cpp",
    sha256 = "758e1eca8186b962516c0659b34ce1768ba1c9769cfd998c5bbffb084ad901ff",
    strip_prefix = "google-cloud-cpp-2.29.0",
    url = "https://github.com/googleapis/google-cloud-cpp/archive/v2.29.0.tar.gz",
)

load("@google_cloud_cpp//bazel:google_cloud_cpp_deps.bzl", "google_cloud_cpp_deps")

google_cloud_cpp_deps()

load("@com_google_googleapis//:repository_rules.bzl", "switched_rules_by_language")

switched_rules_by_language(
    name = "com_google_googleapis_imports",
    cc = True,
    grpc = True,
)

local_repository(
    name = "kv-test-client",
    path = "client/kv-test-client",
)

# NOTE: For kokoro, make sure submodule is on commit, and patches are applied in script
git_repository(
    name = "google_privacysandbox_servers_common",
    commit = "8e3a351b33ed127e52584b7769ece6205492b725",
    patches = [
        "//patches/parc:parc.patch",
    ],
    remote = "sso://team/privacy-sandbox-team/servers/common",
)

load("@google_privacysandbox_servers_common//third_party:cpp_deps.bzl", parc_cpp_dep = "cpp_dependencies")

parc_cpp_dep()

load("@google_privacysandbox_servers_common//third_party:deps1.bzl", parc_dep1 = "deps1")

parc_dep1()

load("@google_privacysandbox_servers_common//third_party:deps2.bzl", parc_dep2 = "deps2")

parc_dep2()

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

oci_pull(
    name = "oak_containers_sysimage_base",
    digest = "sha256:9c88d3bed17cb49e4754de5b0ac7ed5cae3a7d033268278510c08c46b366f5d7",
    image = "europe-west2-docker.pkg.dev/oak-ci/oak-containers-sysimage-base/oak-containers-sysimage-base@sha256:9c88d3bed17cb49e4754de5b0ac7ed5cae3a7d033268278510c08c46b366f5d7",
)

load("@oak//bazel:repositories.bzl", "oak_toolchain_repositories")

oak_toolchain_repositories()

# Hermetic toolchain for binary portability.
# https://blog.aspect.build/hermetic-c-toolchain
# https://github.com/bazelbuild/examples/tree/main/cpp-tutorial/stage0
http_archive(
    name = "aspect_gcc_toolchain",
    sha256 = "3341394b1376fb96a87ac3ca01c582f7f18e7dc5e16e8cf40880a31dd7ac0e1e",
    strip_prefix = "gcc-toolchain-0.4.2",
    urls = [
        "https://github.com/aspect-build/gcc-toolchain/archive/refs/tags/0.4.2.tar.gz",
    ],
)

load("@aspect_gcc_toolchain//toolchain:repositories.bzl", "gcc_toolchain_dependencies")

gcc_toolchain_dependencies()

load("@aspect_gcc_toolchain//toolchain:defs.bzl", "ARCHS", "gcc_register_toolchain")

gcc_register_toolchain(
    name = "gcc_toolchain_x86_64",
    sysroot_variant = "x86_64",
    target_arch = ARCHS.x86_64,
)

gcc_register_toolchain(
    name = "gcc_toolchain_x86_64_unknown_none",
    extra_ldflags = ["-nostdlib"],
    target_arch = ARCHS.x86_64,
    target_compatible_with = [
        "@platforms//cpu:x86_64",
        "@platforms//os:none",
    ],
)

# Declare submodules as local repository so that `build //...` doesn't try to build them.
local_repository(
    name = "submodule1",
    path = "submodules/kv-server",
)

local_repository(
    name = "submodule2",
    path = "submodules/oak",
)

local_repository(
    name = "submodule3",
    path = "submodules/common",
)

local_repository(
    name = "submodule4",
    path = "submodules/bidding-auction-server",
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
