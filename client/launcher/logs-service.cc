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

#include "absl/log/log.h"
#include "opentelemetry/proto/collector/logs/v1/logs_service.pb.h"
#include "opentelemetry/proto/logs/v1/logs.pb.h"

namespace pcit::client {

namespace {

std::optional<absl::string_view> MaybeGetValueForSystemdUnit(
    const opentelemetry::proto::logs::v1::LogRecord& log_record) {
  for (const auto& attribute : log_record.attributes()) {
    if (attribute.key() == "_SYSTEMD_UNIT") {
      return attribute.value().string_value();
    }
  }
  return std::nullopt;
}

}  // namespace

grpc::Status LogsService::Export(
    grpc::ServerContext* context,
    const opentelemetry::proto::collector::logs::v1::ExportLogsServiceRequest*
        request,
    opentelemetry::proto::collector::logs::v1::ExportLogsServiceResponse*
        response) {
  for (const opentelemetry::proto::logs::v1::ResourceLogs& resource_log :
       request->resource_logs()) {
    for (const opentelemetry::proto::logs::v1::ScopeLogs& scope_log :
         resource_log.scope_logs()) {
      for (const opentelemetry::proto::logs::v1::LogRecord& log_record :
           scope_log.log_records()) {
        if (!log_record.body().has_string_value()) {
          continue;
        }
        if (std::optional<absl::string_view> systemd_unit =
                MaybeGetValueForSystemdUnit(log_record);
            systemd_unit.has_value()) {
          LOG(INFO) << *systemd_unit << ": "
                    << log_record.body().string_value();
        }
      }
    }
  }
  return grpc::Status::OK;
}

}  // namespace pcit::client
