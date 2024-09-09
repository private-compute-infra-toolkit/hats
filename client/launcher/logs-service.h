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

#ifndef HATS_CLIENT_LAUNCHER_LOGS_SERVICE_H_
#define HATS_CLIENT_LAUNCHER_LOGS_SERVICE_H_

#include "opentelemetry/proto/collector/logs/v1/logs_service.grpc.pb.h"
#include "opentelemetry/proto/collector/logs/v1/logs_service.pb.h"

namespace privacy_sandbox::client {

// C++ implementation of Oak's LogService
// https://github.com/project-oak/oak/blob/385d5d40f9da5f0ab1df8d4e3ddfa0062b813490/oak_containers/launcher/src/server.rs#L232
// The service receives logs from components running in a CVM, and prints them
// out.
class LogsService final
    : public opentelemetry::proto::collector::logs::v1::LogsService::Service {
 public:
  grpc::Status Export(
      grpc::ServerContext* context,
      const opentelemetry::proto::collector::logs::v1::ExportLogsServiceRequest*
          request,
      opentelemetry::proto::collector::logs::v1::ExportLogsServiceResponse*
          response) override;
};

}  // namespace privacy_sandbox::client

#endif  // HATS_CLIENT_LAUNCHER_LOGS_SERVICE_H_
