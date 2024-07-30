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

#ifndef HATS_CLIENT_LAUNCHER_FORWARDING_TVS_SERVER_
#define HATS_CLIENT_LAUNCHER_FORWARDING_TVS_SERVER_

#include "client/proto/launcher.grpc.pb.h"
#include "client/proto/launcher.pb.h"
#include "grpcpp/support/status.h"
#include "grpcpp/support/sync_stream.h"
#include "tvs/proto/tvs.grpc.pb.h"
#include "tvs/proto/tvs_messages.pb.h"

namespace privacy_sandbox::tvs {

// Grpc server that pipes messages between the client and the server.
// The server is used to proxy communication between the orchestrator
// and Tvs.
// TODO(sidachen): Rename to LauncherService.
class ForwardingTvsServer final
    : public privacy_sandbox::client::LauncherService::Service {
 public:
  ForwardingTvsServer(std::shared_ptr<grpc::Channel> channel);
  grpc::Status VerifyReport(
      grpc::ServerContext* context,
      grpc::ServerReaderWriter<OpaqueMessage, OpaqueMessage>* stream) override;

  grpc::Status FetchTeeCertificate(
      grpc::ServerContext* context, const google::protobuf::Empty* request,
      privacy_sandbox::client::FetchTeeCertificateResponse* reply) override;

 private:
  std::unique_ptr<TeeVerificationService::Stub> stub_;
};

// Starts a server and blocks forever.
void CreateAndStartForwardingTvsServer(int port,
                                       std::shared_ptr<grpc::Channel> channel);

}  // namespace privacy_sandbox::tvs

#endif  // HATS_CLIENT_LAUNCHER_FORWARDING_TVS_SERVER_
