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

load("@com_github_grpc_grpc//bazel:cc_grpc_library.bzl", "cc_grpc_library")
load("@rules_cc//cc:defs.bzl", "cc_proto_library")
load("@rules_proto//proto:defs.bzl", "proto_library")

package(
    default_visibility = ["//visibility:public"],
)

proto_library(
    name = "tvs_messages_proto",
    srcs = ["tvs_messages.proto"],
    deps = [
        "@oak//proto/attestation:evidence_proto",
    ],
)

cc_proto_library(
    name = "tvs_messages_cc_proto",
    deps = [":tvs_messages_proto"],
)

proto_library(
    name = "tvs_proto",
    srcs = ["tvs.proto"],
    deps = [":tvs_messages_proto"],
)

cc_proto_library(
    name = "tvs_cc_proto",
    deps = ["tvs_proto"],
)

cc_grpc_library(
    name = "tvs_cc_grpc",
    srcs = ["tvs_proto"],
    grpc_only = True,
    tags = ["grpc"],
    deps = [":tvs_cc_proto"],
)

proto_library(
    name = "appraisal_policies_proto",
    srcs = ["appraisal_policies.proto"],
    deps = [
        "@oak//proto/attestation:reference_value_proto",
        "@oak//proto/attestation:tcb_version_proto",
    ],
)

cc_proto_library(
    name = "appraisal_policies_cc_proto",
    deps = [":appraisal_policies_proto"],
)
