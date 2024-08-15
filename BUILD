load("@rules_foreign_cc//foreign_cc:defs.bzl", "cmake")

licenses(["notice"])

exports_files(["LICENSE"])

config_setting(
    name = "gcp",
    define_values = {
        "platform": "gcp",
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
