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

#include "tvs/untrusted_tvs/tvs-service.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "grpcpp/security/server_credentials.h"
#include "grpcpp/server.h"
#include "grpcpp/server_builder.h"
#include "grpcpp/server_context.h"
#include "grpcpp/support/status.h"
#include "grpcpp/support/sync_stream.h"
#include "tvs/proto/appraisal_policies.pb.h"
#include "tvs/proto/tvs_messages.pb.h"
#include "tvs/trusted_tvs/trusted_tvs.rs.h"

namespace privacy_sandbox::tvs {

namespace {

rust::Slice<const std::uint8_t> StringToRustSlice(const std::string& str) {
  return rust::Slice<const std::uint8_t>(
      reinterpret_cast<const unsigned char*>(str.data()), str.size());
}

std::string RustVecToString(const rust::Vec<std::uint8_t>& vec) {
  return std::string(reinterpret_cast<const char*>(vec.data()), vec.size());
}

absl::StatusOr<rust::Box<RequestHandler>> CreateRequestHandlerService(
    const std::string& primary_private_key,
    const std::string& secondary_private_key,
    const AppraisalPolicies& appraisal_policies, bool enable_policy_signature,
    bool accept_insecure_policies) {
  if (secondary_private_key.empty()) {
    return NewRequestHandler(
        absl::ToUnixMillis(absl::Now()), StringToRustSlice(primary_private_key),
        StringToRustSlice(appraisal_policies.SerializeAsString()),
        /*user=*/"default", enable_policy_signature, accept_insecure_policies);
  } else {
    return NewRequestHandler(
        absl::ToUnixMillis(absl::Now()), StringToRustSlice(primary_private_key),
        StringToRustSlice(secondary_private_key),
        StringToRustSlice(appraisal_policies.SerializeAsString()),
        /*user=*/"default", enable_policy_signature, accept_insecure_policies);
  }
}

}  // namespace

TvsService::TvsService(const std::string& primary_private_key,
                       AppraisalPolicies appraisal_policies,
                       bool enable_policy_signature,
                       bool accept_insecure_policies)
    : primary_private_key_(primary_private_key),
      appraisal_policies_(std::move(appraisal_policies)),
      enable_policy_signature_(enable_policy_signature),
      accept_insecure_policies_(accept_insecure_policies) {}

TvsService::TvsService(const std::string& primary_private_key,
                       const std::string& secondary_private_key,
                       AppraisalPolicies appraisal_policies,
                       bool enable_policy_signature,
                       bool accept_insecure_policies)
    : primary_private_key_(primary_private_key),
      secondary_private_key_(secondary_private_key),
      appraisal_policies_(std::move(appraisal_policies)),
      enable_policy_signature_(enable_policy_signature),
      accept_insecure_policies_(accept_insecure_policies) {}

grpc::Status TvsService::VerifyReport(
    grpc::ServerContext* context,
    grpc::ServerReaderWriter<OpaqueMessage, OpaqueMessage>* stream) {
  absl::StatusOr<rust::Box<RequestHandler>> trusted_tvs =
      CreateRequestHandlerService(primary_private_key_, secondary_private_key_,
                                  appraisal_policies_, enable_policy_signature_,
                                  accept_insecure_policies_);
  if (!trusted_tvs.ok()) {
    return grpc::Status(grpc::StatusCode::INTERNAL,
                        absl::StrCat("Cannot create trusted TVS server. ",
                                     trusted_tvs.status().ToString()));
  }
  OpaqueMessage request;
  while (stream->Read(&request) && !(*trusted_tvs)->IsTerminated()) {
    absl::StatusOr<rust::Vec<uint8_t>> result =
        (*trusted_tvs)
            ->VerifyReport(StringToRustSlice(request.binary_message()));
    if (!result.ok()) {
      return grpc::Status(
          grpc::StatusCode::INVALID_ARGUMENT,
          absl::StrCat("Invalid or malformed command. ", result.status()));
    }
    OpaqueMessage response;
    response.set_binary_message(RustVecToString(*result));
    if (!stream->Write(response)) {
      LOG(ERROR) << "Failed to write message to stream";
      return grpc::Status(grpc::StatusCode::UNKNOWN,
                          "Failed to write message to stream");
    }
  }
  return grpc::Status::OK;
}

void CreateAndStartTvsServer(TvsServerOptions options) {
  const std::string server_address = absl::StrCat("0.0.0.0:", options.port);
  TvsService tvs_service(
      options.primary_private_key, options.secondary_private_key,
      std::move(options.appraisal_policies), options.enable_policy_signature,
      options.accept_insecure_policies);
  std::unique_ptr<grpc::Server> server =
      grpc::ServerBuilder()
          .AddListeningPort(server_address, grpc::InsecureServerCredentials())
          .RegisterService(&tvs_service)
          .BuildAndStart();
  LOG(INFO) << "Server listening on " << server_address;
  server->Wait();
}

}  // namespace privacy_sandbox::tvs
