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

#ifndef HATS_TVS_UNTRUSTED_TVS_SERVER_
#define HATS_TVS_UNTRUSTED_TVS_SERVER_

#include <string>

#include "grpcpp/server_context.h"
#include "grpcpp/support/status.h"
#include "grpcpp/support/sync_stream.h"
#include "tvs/proto/appraisal_policies.pb.h"
#include "tvs/proto/tvs.grpc.pb.h"
#include "tvs/proto/tvs_messages.pb.h"

namespace privacy_sandbox::tvs {

// An implementation of TeeVerificationService.
// The service exports one bidirectional streaming rpc, namely VerifyReport.
// The server acts as a pipe between clients and the trusted tee verification
// service. The server is agnostic toe the messages. It receives bytes from gRPC
// clients, passes them to the trusted TVS, and pass back bytes received from
// the trusted TVS to client. The trusted TVS expect the following flow:
// 1. Client initiate noise handshake.
// 2. Server responds to the handshake with an ephemeral public key.
// 3. Client sends attestation report.
// 4. Server verifies the report and returns a secret.
class TvsServer final : public TeeVerificationService::Service {
 public:
  // Pass appraisal_policy by value as we expect the caller to use std::move().
  explicit TvsServer(const std::string& primary_private_key,
                     AppraisalPolicies appraisal_policies,
                     const bool enable_policy_signature = true);
  explicit TvsServer(const std::string& primary_private_key,
                     const std::string& secondary_private_key,
                     AppraisalPolicies appraisal_policies,
                     const bool enable_policy_signature = true);

  TvsServer() = delete;
  grpc::Status VerifyReport(
      grpc::ServerContext* context,
      grpc::ServerReaderWriter<OpaqueMessage, OpaqueMessage>* stream) override;

 private:
  const std::string primary_private_key_;
  const std::string secondary_private_key_;
  const AppraisalPolicies appraisal_policies_;
  const bool enable_policy_signature_;
};

struct TvsServerOptions {
  int port;
  std::string primary_private_key;
  std::string secondary_private_key;
  AppraisalPolicies appraisal_policies;
  const bool enable_policy_signature;
};

// Starts a server and blocks forever.
// Pass by value as we expect the caller to use std::move() or use temporaries.
void CreateAndStartTvsServer(TvsServerOptions options);

}  // namespace privacy_sandbox::tvs

#endif  // HATS_TVS_UNTRUSTED_TVS_SERVER_
