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

load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")

package(
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "otel-local",
    srcs = ["otel-local.cc"],
    hdrs =
        [
            "otel.h",
        ],
    deps =
        [
            "@com_github_grpc_grpc//:grpc++",
            "@com_github_grpc_grpc//:grpcpp_otel_plugin",
            "@com_google_absl//absl/status",
            "@io_opentelemetry_cpp//exporters/otlp:otlp_grpc_metric_exporter",
            "@io_opentelemetry_cpp//sdk/src/metrics",
        ],
)

cc_library(
    name = "otel-noop",
    srcs = ["otel-noop.cc"],
    hdrs =
        [
            "otel.h",
        ],
    deps = [
        "@com_google_absl//absl/status",
    ],
)

cc_library(
    name = "otel-counter",
    srcs = ["otel-counter.cc"],
    hdrs =
        [
            "otel-counter.h",
        ],
    deps =
        [
            "@com_google_absl//absl/strings",
            "@io_opentelemetry_cpp//sdk/src/metrics",
        ],
)

cc_test(
    name = "otel-counter_test",
    size = "small",
    srcs = [":otel-counter_test.cc"],
    deps = [
        ":otel-counter",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
        "@io_opentelemetry_cpp//exporters/memory:in_memory_metric_exporter_factory",
        "@io_opentelemetry_cpp//sdk/src/metrics",
    ],
)
