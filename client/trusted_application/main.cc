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

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/flags.h"  // IWYU pragma: keep
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "client/proto/orchestrator.grpc.pb.h"
#include "client/proto/orchestrator.pb.h"
#include "client/sdk/hats_orchestrator_client.h"
#include "client/trusted_application/trusted_application.h"
#include "grpcpp/security/server_credentials.h"
#include "grpcpp/server.h"
#include "grpcpp/server_builder.h"

ABSL_FLAG(std::string, port, "8080",
          "port used for making grpc calls to this service");

int main(int argc, char* argv[]) {
  absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();

  std::string port_to_use = absl::GetFlag(FLAGS_port);
  privacy_sandbox::server_common::HatsOrchestratorClient client =
      privacy_sandbox::server_common::HatsOrchestratorClient();

  absl::StatusOr<std::vector<privacy_sandbox::server_common::Key>> keys =
      client.GetKeys();

  privacy_sandbox::client::TrustedApplication service(*std::move(keys));

  grpc::ServerBuilder builder;
  builder.AddListeningPort(absl::StrCat("[::]:", port_to_use),
                           grpc::InsecureServerCredentials());
  builder.RegisterService(&service);
  std::unique_ptr<grpc::Server> server(builder.BuildAndStart());

  absl::Status app_ready = client.NotifyAppReady();
  if (!app_ready.ok()) {
    LOG(ERROR) << "Failed to notify launcher that app is ready: "
               << app_ready.message();
    return 1;
  }

  std::cout << "Trusted Application is running on port " << port_to_use
            << std::endl;

  server->Wait();
  return 0;
}
