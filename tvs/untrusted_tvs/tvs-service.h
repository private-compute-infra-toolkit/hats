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

#ifndef HATS_TVS_UNTRUSTED_TVS_SERVICE_
#define HATS_TVS_UNTRUSTED_TVS_SERVICE_

#include <memory>
#include <string>

#include "grpcpp/server_context.h"
#include "grpcpp/support/status.h"
#include "grpcpp/support/sync_stream.h"
#include "key_manager/key-fetcher.h"
#include "tvs/proto/appraisal_policies.pb.h"
#include "tvs/proto/tvs.grpc.pb.h"
#include "tvs/proto/tvs_messages.pb.h"
#include "tvs/untrusted_tvs/launcher.rs.h"

namespace privacy_sandbox::tvs {

// An implementation of TeeVerificationService.
// The service exports one bidirectional streaming rpc, namely VerifyReport.
// The server acts as a pipe between clients and the trusted tee verification
// service. The server launches a VMM that runs the trusted software.
// The server is agnostic to the messages. It receives bytes from gRPC
// clients, passes them to the trusted TVS, and pass back bytes received from
// the trusted TVS to client. The trusted TVS expect the following flow:
// 1. Client initiate noise handshake.
// 2. Server responds to the handshake with an ephemeral public key.
// 3. Client sends attestation report.
// 4. Server verifies the report and returns a secret.
class TvsService final : public TeeVerificationService::Service {
 public:
  struct Options {
    std::unique_ptr<key_manager::KeyFetcher> key_fetcher;
    AppraisalPolicies appraisal_policies;
    std::string vmm_binary;
    std::string bios_binary;
    std::string kernel;
    std::string initrd;
    std::string app_binary;
    std::string memory_size;
  };

  explicit TvsService(rust::Box<Launcher> launcher,
                      std::unique_ptr<key_manager::KeyFetcher> key_fetcher);
  TvsService() = delete;
  // `options` is passed by value to enable effective use of move.
  // Caller should utilize std::move() to avoid unnecessary copies.
  static absl::StatusOr<std::unique_ptr<TvsService>> Create(Options options);

  grpc::Status VerifyReport(
      grpc::ServerContext* context,
      grpc::ServerReaderWriter<OpaqueMessage, OpaqueMessage>* stream) override;

 private:
  rust::Box<Launcher> launcher_;
  std::unique_ptr<key_manager::KeyFetcher> key_fetcher_;
};

}  // namespace privacy_sandbox::tvs

#endif  // HATS_TVS_UNTRUSTED_TVS_SERVICE_
