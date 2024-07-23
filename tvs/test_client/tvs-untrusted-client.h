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

#ifndef HATS_TVS_TEST_CLIENT_TVS_UNTRUSTED_CLIENT_H_
#define HATS_TVS_TEST_CLIENT_TVS_UNTRUSTED_CLIENT_H_

#include <memory>
#include <string>

#include "absl/status/statusor.h"
#include "client/proto/launcher.grpc.pb.h"
#include "grpcpp/channel.h"
#include "grpcpp/client_context.h"
#include "grpcpp/support/sync_stream.h"
#include "tvs/client/trusted-client.rs.h"
#include "tvs/proto/tvs.grpc.pb.h"
#include "tvs/proto/tvs_messages.pb.h"

namespace privacy_sandbox::tvs {

// Communicate with a TVS server and fetches a JWT token. The class sends an
// attestation report and gets a JWT token from a TVS server over a streaming
// gRPC channel. The class performs noise handshake, and necessary proto
// encoding/decoding.
class TvsUntrustedClient final {
  struct Options {
    std::string tvs_public_key;
    std::shared_ptr<grpc::Channel> channel = nullptr;
    bool use_launcher_forwarding = false;
  };

 public:
  TvsUntrustedClient() = delete;
  TvsUntrustedClient(const TvsUntrustedClient& arg) = delete;
  TvsUntrustedClient(TvsUntrustedClient&& arg) = delete;
  TvsUntrustedClient& operator=(const TvsUntrustedClient& rhs) = delete;
  TvsUntrustedClient& operator=(TvsUntrustedClient& rhs) = delete;

  static absl::StatusOr<std::unique_ptr<TvsUntrustedClient>> CreateClient(
      const Options& options);

  // Get JWT token from TVS server.
  absl::StatusOr<std::string> VerifyReportAndGetToken(
      const std::string& application_signing_key,
      const VerifyReportRequest& verify_report_request);

 private:
  TvsUntrustedClient(
      std::unique_ptr<privacy_sandbox::client::LauncherService::Stub>
          launcher_stub_,
      std::unique_ptr<TeeVerificationService::Stub> stub,
      std::unique_ptr<grpc::ClientContext> context,
      std::unique_ptr<grpc::ClientReaderWriter<OpaqueMessage, OpaqueMessage>>
          stream,
      rust::Box<TvsClient> tvs_client);

  std::unique_ptr<privacy_sandbox::client::LauncherService::Stub>
      launcher_stub_;
  std::unique_ptr<TeeVerificationService::Stub> stub_;
  std::unique_ptr<grpc::ClientContext> context_;
  std::unique_ptr<grpc::ClientReaderWriter<OpaqueMessage, OpaqueMessage>>
      stream_;
  rust::Box<TvsClient> tvs_client_;
};

}  // namespace privacy_sandbox::tvs

#endif  // HATS_TVS_TEST_CLIENT_TVS_UNTRUSTED_CLIENT_H_
