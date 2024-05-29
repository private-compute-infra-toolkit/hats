workspace(name = "hats")

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

# Pull a remote copy of oak to patch proto include paths. The relative paths changes
# if Oak is an external repo itself. We should use oak repository in the submodules;
# however, local_repository does not support patching.
# TODO(alwabel): use local_repository. This might require writing a custom bazel script to patch files.
http_archive(
    name = "oak",
    patches = [
        "//patches/oak:proto_dependency.patch",
    ],
    sha256 = "586b85edaccbf7a586e73812abc499999385fbbf901c98b37e977507187c85fb",
    strip_prefix = "oak-65892800827299af01330100c3aee9fa0d90c4ee",
    url = "https://github.com/project-oak/oak/archive/65892800827299af01330100c3aee9fa0d90c4ee.tar.gz",
)

load("@rules_rust//crate_universe:repositories.bzl", "crate_universe_dependencies")

crate_universe_dependencies()

load("@rules_rust//crate_universe:defs.bzl", "crate", "crates_repository")

# Stash packages used by rust code in a repository.
crates_repository(
    name = "hats_crate_index",
    cargo_lockfile = "//:Cargo.bazel.lock",
    lockfile = "//:cargo-bazel-lock.json",
    packages = {
        "cxx": crate.spec(version = "*"),
        "hex": crate.spec(version = "*"),
        "jwt-simple": crate.spec(version = "*"),
        "prost": crate.spec(
            default_features = False,
            features = ["prost-derive"],
            version = "*",
        ),
    },
)

load("@hats_crate_index//:defs.bzl", hats_crate_repositories = "crate_repositories")

hats_crate_repositories()

# Create oak_crates_index repository that is used by oak libraries.
# We rely on Cargo.toml to generate the dependencies needed by oak libraries.
# We manually overrides dependencies to overcome compliation issues, the overrides
# are copied from oak WORKSPACE.
crates_repository(
    name = "oak_crates_index",
    cargo_lockfile = "//:Cargo.oak.bazel.lock",
    lockfile = "//:cargo-oak-bazel-lock.json",
    manifests = [
        "//:Cargo.toml",
        "//tvs/trusted_tvs:Cargo.toml",
    ],
    packages = {
        "curve25519-dalek": crate.spec(
            default_features = False,
            version = "=4.1.1",
        ),
    },
)

load("@oak_crates_index//:defs.bzl", oak_crate_repositories = "crate_repositories")

oak_crate_repositories()
