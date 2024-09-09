// Copyright 2024 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "client/launcher/logs-service.h"

#include <memory>

#include "absl/base/log_severity.h"
#include "absl/log/scoped_mock_log.h"
#include "gmock/gmock.h"
#include "google/protobuf/text_format.h"
#include "grpcpp/server.h"
#include "grpcpp/server_builder.h"
#include "grpcpp/support/channel_arguments.h"
#include "grpcpp/support/status.h"
#include "gtest/gtest.h"
#include "opentelemetry/proto/collector/logs/v1/logs_service.grpc.pb.h"
#include "opentelemetry/proto/collector/logs/v1/logs_service.pb.h"

namespace privacy_sandbox::client {
namespace {

using ::absl::LogSeverity;
using ::absl::ScopedMockLog;
using ::testing::_;

TEST(LogsService, Successful) {
  LogsService logs_service;
  std::unique_ptr<grpc::Server> logs_server =
      grpc::ServerBuilder().RegisterService(&logs_service).BuildAndStart();
  //  log_server.
  std::unique_ptr<opentelemetry::proto::collector::logs::v1::LogsService::Stub>
      stub = opentelemetry::proto::collector::logs::v1::LogsService::NewStub(
          logs_server->InProcessChannel(grpc::ChannelArguments()));
  grpc::ClientContext client_context;
  opentelemetry::proto::collector::logs::v1::ExportLogsServiceRequest request;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      R"pb(resource_logs {
             resource {
               attributes {
                 key: "service.name"
                 value { string_value: "unknown_service" }
               }
             }
             scope_logs {
               log_records {
                 severity_number: SEVERITY_NUMBER_INFO2
                 body { string_value: "Linux" }
                 attributes {
                   key: "_HOSTNAME"
                   value { string_value: "localhost" }
                 }
                 attributes {
                   key: "_MACHINE_ID"
                   value { int_value: 34 }
                 }
                 attributes {
                   key: "_SYSTEMD_UNIT"
                   value { string_value: "systemd-journald.service" }
                 }
               }
             }
           }
           resource_logs {
             # This log should be ignored since the body does not have string
             # value
             scope_logs {
               log_records {
                 severity_number: SEVERITY_NUMBER_INFO2
                 body { int_value: 30 }
                 attributes {
                   key: "_SYSTEMD_UNIT"
                   value { string_value: "systemd-journald.service" }
                 }
               }
             }
           }
           resource_logs {
             scope_logs {
               log_records {
                 severity_number: SEVERITY_NUMBER_INFO
                 body { string_value: "orchestrator" }
                 attributes {
                   key: "_SYSTEMD_UNIT"
                   value { string_value: "systemd-journald.service" }
                 }
               }
             }
           })pb",
      &request));

  ScopedMockLog log;
  EXPECT_CALL(log,
              Log(LogSeverity::kInfo, _, "systemd-journald.service: Linux"));
  EXPECT_CALL(log, Log(LogSeverity::kInfo, _,
                       "systemd-journald.service: orchestrator"));
  opentelemetry::proto::collector::logs::v1::ExportLogsServiceResponse response;
  log.StartCapturingLogs();
  grpc::Status status = stub->Export(&client_context, request, &response);
  ASSERT_TRUE(status.ok());
}

}  // namespace
}  // namespace privacy_sandbox::client
