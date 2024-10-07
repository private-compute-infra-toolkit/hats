# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")

package(
    default_visibility = ["//visibility:public"],
)

cc_binary(
    name = "tvs-client_main",
    testonly = True,
    srcs = ["tvs-client_main.cc"],
    deps = [
        ":tvs-untrusted-client",
        "//status_macro:status_macros",
        "//tvs/credentials",
        "//tvs/proto:tvs_messages_cc_proto",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:flags",
        "@com_google_absl//absl/log:initialize",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf",
        "@com_google_protobuf//src/google/protobuf/io",
    ],
)

cc_binary(
    name = "tvs-client-split_main",
    testonly = True,
    srcs = ["tvs-client-split_main.cc"],
    deps = [
        ":tvs-untrusted-client",
        "//crypto:aead-crypter",
        "//crypto:bridge",
        "//crypto:secret-data",
        "//status_macro:status_macros",
        "//tvs/credentials",
        "//tvs/proto:tvs_messages_cc_proto",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:flags",
        "@com_google_absl//absl/log:initialize",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf",
        "@com_google_protobuf//src/google/protobuf/io",
        "@hats_crate_index//:hex",
    ],
)

cc_library(
    name = "tvs-untrusted-client",
    testonly = True,
    srcs = ["tvs-untrusted-client.cc"],
    hdrs = ["tvs-untrusted-client.h"],
    deps = [
        "//status_macro:status_macros",
        "//tvs/client:bridge",
        "//tvs/client:bridge/include",
        "//tvs/proto:tvs_cc_grpc",
        "//tvs/proto:tvs_messages_cc_proto",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)
