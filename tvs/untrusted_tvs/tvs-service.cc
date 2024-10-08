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
#include "grpcpp/server_context.h"
#include "grpcpp/support/status.h"
#include "grpcpp/support/sync_stream.h"
#include "key_manager/key-fetcher.h"
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

}  // namespace

TvsService::TvsService(rust::Box<trusted::Service> trusted_service)
    : trusted_service_(std::move(trusted_service)) {}

absl::StatusOr<std::unique_ptr<TvsService>> TvsService::Create(
    Options options) {
  absl::StatusOr<rust::Box<trusted::Service>> trusted_service =
      trusted::NewService(
          std::make_unique<trusted::KeyFetcherWrapper>(
              std::move(options.key_fetcher)),
          StringToRustSlice(options.appraisal_policies.SerializeAsString()),
          options.enable_policy_signature, options.accept_insecure_policies);

  // Note: Status macros currently don't support setting the status code, and
  // the test checks the code type.
  if (!trusted_service.ok()) {
    return absl::FailedPreconditionError(absl::StrCat(
        "Cannot create trusted TVS server: ", trusted_service.status()));
  }
  return std::make_unique<TvsService>(*std::move(trusted_service));
}

grpc::Status TvsService::VerifyReport(
    grpc::ServerContext* context,
    grpc::ServerReaderWriter<OpaqueMessage, OpaqueMessage>* stream) {
  rust::Box<trusted::RequestHandler> request_handler =
      trusted_service_->CreateRequestHandler(absl::ToUnixMillis(absl::Now()),
                                             /*user=*/"default");
  OpaqueMessage request;
  while (stream->Read(&request) && !request_handler->IsTerminated()) {
    absl::StatusOr<rust::Vec<uint8_t>> result = request_handler->VerifyReport(
        StringToRustSlice(request.binary_message()));
    // Note: Status macros currently don't support setting the status code, and
    // the test checks the code type.
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

}  // namespace privacy_sandbox::tvs
