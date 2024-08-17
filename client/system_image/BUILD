load("@oak//bazel:defs.bzl", "oci_runtime_bundle")
load("@rules_oci//oci:defs.bzl", "oci_image")
load("@rules_pkg//pkg:tar.bzl", "pkg_tar")

# Change oak-orchestrator.service to load hats orchestrator
# and bake the TVS public key in the file.
pkg_tar(
    name = "services",
    srcs = ["oak-orchestrator.service"],
    package_dir = "/etc/systemd/system/",
    tags = ["nopresubmit"],
)

# Override the enp0s1 interface settings as we are setting
# the networking through kernel NFS flags.
pkg_tar(
    name = "interface",
    srcs = ["10-enp0s1.network"],
    package_dir = "/etc/systemd/network/",
    tags = ["nopresubmit"],
)

# Administrative binaries.
pkg_tar(
    name = "admin_bin",
    srcs = [
        "//client/orchestrator:orchestrator_main",
        "@oak//oak_containers_agent",
    ] + select({
        # Build syslogd only if the user specifically enabled it
        # oak_containers_syslogd requires libsystemd.so during the
        # build, which might not exists.
        "//:syslogd_enabled": ["@oak//oak_containers_syslogd"],
        "//conditions:default": [],
    }),
    package_dir = "/usr/bin/",
    tags = ["nopresubmit"],
)

oci_image(
    name = "hats_system_oci_image",
    base = "@oak_containers_sysimage_base",
    tags = ["nopresubmit"],
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
    tags = ["nopresubmit"],
)
