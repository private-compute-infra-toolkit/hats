load("@bazel_skylib//rules:common_settings.bzl", "string_flag")
load("@rules_foreign_cc//foreign_cc:defs.bzl", "cmake")

licenses(["notice"])

exports_files(["LICENSE"])

config_setting(
    name = "gcp",
    define_values = {
        "platform": "gcp",
    },
)

# Whether or not to build oak_containers_syslogd.
string_flag(
    name = "enable_syslogd",
    build_setting_default = "false",
    values = [
        "false",
        "true",
    ],
)

config_setting(
    name = "syslogd_disabled",
    flag_values = {
        ":enable_syslogd": "false",
    },
)

config_setting(
    name = "syslogd_enabled",
    flag_values = {
        ":enable_syslogd": "true",
    },
)

# Foreign CMake library must be declared in a BUILD file.
cmake(
    name = "libarchive",
    cache_entries = {
        "CMAKE_C_FLAGS": "-fPIC",
    },
    lib_source = "@libarchive//:all_srcs",
    out_static_libs = ["libarchive.a"],
    visibility = ["//visibility:public"],
)
