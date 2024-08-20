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

#ifndef HATS_CLIENT_LAUNCHER_LAUNCHER_SERVER_
#define HATS_CLIENT_LAUNCHER_LAUNCHER_SERVER_

#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "client/proto/launcher.grpc.pb.h"
#include "client/proto/launcher.pb.h"
#include "grpcpp/support/status.h"
#include "grpcpp/support/sync_stream.h"
#include "tvs/proto/tvs.grpc.pb.h"
#include "tvs/proto/tvs_messages.pb.h"

namespace privacy_sandbox::client {

class LauncherServer final
    : public privacy_sandbox::client::LauncherService::Service {
 public:
  // tvs_authentication_key is in bytes format.
  LauncherServer(absl::string_view tvs_authentication_key,
                 std::shared_ptr<grpc::Channel> channel);
  // Pipes messages between the client and the server.
  // This used to proxy communication between the orchestrator and Tvs.
  grpc::Status VerifyReport(
      grpc::ServerContext* context,
      grpc::ServerReaderWriter<tvs::OpaqueMessage, tvs::OpaqueMessage>* stream)
      override;

  grpc::Status FetchOrchestratorMetadata(
      grpc::ServerContext* context, const google::protobuf::Empty* request,
      privacy_sandbox::client::FetchOrchestratorMetadataResponse* reply)
      override;

 private:
  const std::string tvs_authentication_key_;
  std::unique_ptr<tvs::TeeVerificationService::Stub> stub_;
};

// Starts a server and blocks forever.
void CreateAndStartLauncherServer(int port,
                                  absl::string_view tvs_authentication_key,
                                  std::shared_ptr<grpc::Channel> channel);

}  // namespace privacy_sandbox::client

#endif  // HATS_CLIENT_LAUNCHER_LAUNCHER_SERVER_
