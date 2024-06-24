workspace(name = "hats")

load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@rules_rust//rust:repositories.bzl", "rules_rust_dependencies", "rust_register_toolchains", "rust_repository_set")

rules_rust_dependencies()

rust_register_toolchains(
    edition = "2021",
    versions = [
        "1.76.0",
        "nightly/2024-02-01",
    ],
)

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

load("@rules_rust//bindgen:repositories.bzl", "rust_bindgen_dependencies", "rust_bindgen_register_toolchains")

rust_bindgen_dependencies()

rust_bindgen_register_toolchains()

load("@rules_rust//bindgen:transitive_repositories.bzl", "rust_bindgen_transitive_dependencies")

rust_bindgen_transitive_dependencies()

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

load("@io_grpc_grpc_java//:repositories.bzl", "IO_GRPC_GRPC_JAVA_ARTIFACTS", "IO_GRPC_GRPC_JAVA_OVERRIDE_TARGETS", "grpc_java_repositories")
load("@rules_rust//crate_universe:repositories.bzl", "crate_universe_dependencies")

crate_universe_dependencies(bootstrap = True)

load("@rules_rust//crate_universe:defs.bzl", "crate", "crates_repository", "splicing_config")

# Stash packages used by rust code in a repository.
crates_repository(
    name = "hats_crate_index",
    cargo_lockfile = "//:Cargo.bazel.lock",
    lockfile = "//:cargo-bazel-lock.json",
    packages = {
        "cxx": crate.spec(version = "*"),
        "hex": crate.spec(version = "*"),
        "jwt-simple": crate.spec(
            default_features = False,
            features = ["pure-rust"],
            version = "*",
        ),
        "prost": crate.spec(
            default_features = False,
            features = ["prost-derive"],
            version = "*",
        ),
        "p256": crate.spec(version = "*"),
    },
)

load("@hats_crate_index//:defs.bzl", hats_crate_repositories = "crate_repositories")

hats_crate_repositories()

http_archive(
    name = "oak",
    patches = [
        "//patches/oak:cert_chain.patch",
    ],
    sha256 = "b7f571ccaebe18eb38a4cc08d77b37161485718e4163cd529c2fbe40c00df529",
    strip_prefix = "oak-4c05a0312d0688b3b86c6695b7463df9626d8104",
    url = "https://github.com/project-oak/oak/archive/4c05a0312d0688b3b86c6695b7463df9626d8104.tar.gz",
)

load("@oak//bazel/crates:repositories.bzl", "create_oak_crate_repositories")

create_oak_crate_repositories(
    cargo_lockfile = "//:Cargo_oak.bazel.lock",
    lockfile = "//:cargo-oak-bazel-lock.json",
    no_std_cargo_lockfile = "//:Cargo_oak_no_std.bazel.lock",
    no_std_lockfile = "//:cargo-oak-no-std-bazel-lock.json",
)

load("@oak//bazel/crates:crates.bzl", "load_oak_crate_repositories")

load_oak_crate_repositories()

# CXX bridge setup.
# Mostly copied from https://github.com/bazelbuild/rules_rust/blob/df80ce61e418ea1c45c5bd51f88a440a7fb9ebc9/examples/crate_universe/WORKSPACE.bazel#L502

crates_repository(
    name = "using_cxx",
    cargo_lockfile = "//:Cargo.cxx.bazel.lock",
    # `generator` is not necessary in official releases.
    # See load satement for `cargo_bazel_bootstrap`.
    generator = "@cargo_bazel_bootstrap//:cargo-bazel",
    lockfile = "//:cargo-cxx-bazel-lock.json",
    packages = {
        "cxx": crate.spec(
            version = "1.0.109",
        ),
    },
    splicing_config = splicing_config(
        resolver_version = "2",
    ),
)

load(
    "@using_cxx//:defs.bzl",
    using_cxx_crate_repositories = "crate_repositories",
)

using_cxx_crate_repositories()

# The codegen tool needed by cxx.
http_archive(
    name = "cxxbridge-cmd",
    build_file_content = """
load("@rules_rust//rust:defs.bzl", "rust_binary")
load("@cxxbridge_cmd_deps//:defs.bzl", "aliases", "all_crate_deps")

rust_binary(
    name = "cxxbridge-cmd",
    srcs = glob(["src/**/*.rs"]),
    aliases = aliases(),
    data = [
        "src/gen/include/cxx.h",
    ],
    edition = "2021",
    visibility = ["//visibility:public"],
    deps = all_crate_deps(
        normal = True,
    ),
)
    """,
    sha256 = "d93600487d429c8bf013ee96719af4e62e809ac57fc4cac24f17cf58e4526009",
    strip_prefix = "cxxbridge-cmd-1.0.109",
    type = "tar.gz",
    urls = ["https://crates.io/api/v1/crates/cxxbridge-cmd/1.0.109/download"],
)

crates_repository(
    name = "cxxbridge_cmd_deps",
    cargo_lockfile = "//:Cargo.cxxbridge-cmd.bazel.lock",
    # `generator` is not necessary in official releases.
    # See load satement for `cargo_bazel_bootstrap`.
    generator = "@cargo_bazel_bootstrap//:cargo-bazel",
    lockfile = "//:cargo-cxxbrdige-cmd-bazel-lock.json",
    manifests = ["@cxxbridge-cmd//:Cargo.toml"],
    splicing_config = splicing_config(
        resolver_version = "2",
    ),
)

load("@cxxbridge_cmd_deps//:defs.bzl", cxxbridge_cmd_deps = "crate_repositories")

cxxbridge_cmd_deps()

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
