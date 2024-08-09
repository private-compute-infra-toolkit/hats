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

#include "client/sdk/hats_orchestrator_client.h"

#include <memory>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "client/proto/orchestrator.grpc.pb.h"
#include "client/proto/orchestrator.pb.h"
#include "external/oak/cc/containers/sdk/common.h"
#include "grpcpp/channel.h"

namespace privacy_sandbox::client {

namespace {

absl::Status GrpcToAbslStatus(const grpc::Status& status) {
  switch (status.error_code()) {
    case grpc::StatusCode::OK:
      return absl::OkStatus();
    case grpc::StatusCode::INTERNAL:
      return absl::InternalError(status.error_message());
    case grpc::StatusCode::UNAVAILABLE:
      return absl::UnavailableError(status.error_message());
    case grpc::StatusCode::ABORTED:
      return absl::AbortedError(status.error_message());
    case grpc::StatusCode::OUT_OF_RANGE:
      return absl::OutOfRangeError(status.error_message());
    case grpc::StatusCode::UNIMPLEMENTED:
      return absl::UnimplementedError(status.error_message());
    case grpc::StatusCode::FAILED_PRECONDITION:
      return absl::FailedPreconditionError(status.error_message());
    case grpc::StatusCode::UNAUTHENTICATED:
      return absl::UnauthenticatedError(status.error_message());
    case grpc::StatusCode::PERMISSION_DENIED:
      return absl::PermissionDeniedError(status.error_message());
    case grpc::StatusCode::RESOURCE_EXHAUSTED:
      return absl::ResourceExhaustedError(status.error_message());
    case grpc::StatusCode::DATA_LOSS:
      return absl::DataLossError(status.error_message());
    case grpc::StatusCode::INVALID_ARGUMENT:
      return absl::InvalidArgumentError(status.error_message());
    case grpc::StatusCode::DEADLINE_EXCEEDED:
      return absl::DeadlineExceededError(status.error_message());
    case grpc::StatusCode::NOT_FOUND:
      return absl::NotFoundError(status.error_message());
    case grpc::StatusCode::ALREADY_EXISTS:
      return absl::AlreadyExistsError(status.error_message());
    case grpc::StatusCode::CANCELLED:
      return absl::CancelledError(status.error_message());
    case grpc::StatusCode::UNKNOWN:
      return absl::UnknownError(status.error_message());
    case grpc::StatusCode::DO_NOT_USE:
      return absl::UnknownError(status.error_message());
  }
  return absl::UnknownError(status.error_message());
}

}  // namespace

HatsOrchestratorClient::HatsOrchestratorClient()
    : hats_stub_(HatsOrchestrator::NewStub(
          grpc::CreateChannel(oak::containers::sdk::kOrchestratorSocket,
                              grpc::InsecureChannelCredentials()))) {}

HatsOrchestratorClient::HatsOrchestratorClient(
    std::shared_ptr<grpc::Channel> channel)
    : hats_stub_(HatsOrchestrator::NewStub(channel)) {}

absl::StatusOr<std::string> HatsOrchestratorClient::GetHpkeKey() const {
  grpc::ClientContext context;
  context.set_authority(oak::containers::sdk::kContextAuthority);
  privacy_sandbox::client::GetHpkeKeyResponse response;
  if (grpc::Status status = hats_stub_->GetHpkeKey(&context, {}, &response);
      !status.ok()) {
    return GrpcToAbslStatus(status);
  }
  return response.private_key();
}

}  // namespace privacy_sandbox::client
