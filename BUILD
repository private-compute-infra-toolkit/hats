load("@bazel_skylib//rules:common_settings.bzl", "string_flag")

licenses(["notice"])

exports_files(["LICENSE"])

config_setting(
    name = "gcp",
    define_values = {
        "platform": "gcp",
    },
)

# Where to find oak_containers_syslogd.
string_flag(
    name = "syslogd_source",
    build_setting_default = "none",
    values = [
        # Don't attempt to find oak_containers_syslogd..
        "none",
        # Build oak_containers_syslogd from source.
        "source",
        # oak_containers_syslogd binary is in the prebuilt directory.
        "binary",
    ],
)

config_setting(
    name = "no_syslogd",
    flag_values = {
        ":syslogd_source": "none",
    },
)

config_setting(
    name = "syslogd_from_source",
    flag_values = {
        ":syslogd_source": "source",
    },
)

config_setting(
    name = "syslogd_from_binary",
    flag_values = {
        ":syslogd_source": "binary",
    },
)
