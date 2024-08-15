load("@oak//bazel:defs.bzl", "oci_runtime_bundle")
load("@rules_oci//oci:defs.bzl", "oci_image", "oci_tarball")
load("@rules_pkg//pkg:tar.bzl", "pkg_tar")
load("@rules_rust//rust:defs.bzl", "rust_binary")

# Change oak-orchestrator.service to load hats orchestrator
# and bake the TVS public key in the file.
pkg_tar(
    name = "services",
    srcs = ["oak-orchestrator.service"],
    package_dir = "/etc/systemd/system/",
)

# Override the enp0s1 interface settings as we are setting
# the networking through kernel NFS flags.
pkg_tar(
    name = "interface",
    srcs = ["10-enp0s1.network"],
    package_dir = "/etc/systemd/network/",
)

# Administrative binaries.
pkg_tar(
    name = "admin_bin",
    srcs = [
        "//client/orchestrator:orchestrator_main",
        "@oak//oak_containers_agent",
        "@oak//oak_containers_syslogd",
    ],
    package_dir = "/usr/bin/",
)

oci_image(
    name = "hats_system_oci_image",
    base = "@oak_containers_sysimage_base",
    tars = [
        ":admin_bin",
        ":services",
        ":interface",
    ],
)

oci_runtime_bundle(
    name = "hats_system_image",
    image = ":hats_system_oci_image",
    rootfs_only = True,
)
