load("@bazel_skylib//rules:common_settings.bzl", "string_flag")

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
