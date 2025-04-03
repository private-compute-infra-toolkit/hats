# Copyright 2025 Google LLC
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

cc_library(
    name = "trusted_application_client",
    testonly = 1,
    srcs = ["trusted_application_client.cc"],
    hdrs = ["trusted_application_client.h"],
    deps = [
        "//client/proto:trusted_service_cc_grpc",
        "//client/proto:trusted_service_cc_proto",
        "//crypto:aead-crypter",
        "//crypto:secret-data",
        "//status_macro:status_macros",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings:string_view",
    ],
)

cc_binary(
    name = "trusted_application_client_main",
    testonly = 1,
    srcs = ["trusted_application_client_main.cc"],
    deps = [
        ":trusted_application_client",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log:flags",
        "@com_google_absl//absl/strings",
    ],
)
