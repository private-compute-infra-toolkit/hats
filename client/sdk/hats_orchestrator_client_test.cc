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

#include "absl/status/status_matchers.h"
#include "client/proto/orchestrator.grpc.pb.h"
#include "client/proto/orchestrator.pb.h"
#include "gmock/gmock.h"
#include "grpcpp/server.h"
#include "grpcpp/server_builder.h"
#include "grpcpp/support/channel_arguments.h"
#include "gtest/gtest.h"

namespace privacy_sandbox::client {
namespace {

using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::testing::HasSubstr;
using ::testing::StrEq;

constexpr absl::string_view kTestKey = "private_key";

class TestHatsOrchestratorService final : public HatsOrchestrator::Service {
 public:
  TestHatsOrchestratorService(bool return_error)
      : return_error_(return_error) {}
  grpc::Status GetHpkeKey(grpc::ServerContext* context,
                          const google::protobuf::Empty* request,
                          GetHpkeKeyResponse* response) {
    if (return_error_) {
      return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                          "Invalid argument");
    }
    response->set_private_key(kTestKey);
    return grpc::Status::OK;
  }

 private:
  bool return_error_;
};

TEST(HatsOrchestratorClient, Success) {
  TestHatsOrchestratorService test_service(/*return_error=*/false);
  std::unique_ptr<grpc::Server> server =
      grpc::ServerBuilder().RegisterService(&test_service).BuildAndStart();
  HatsOrchestratorClient hats_orchestrator_client(
      server->InProcessChannel(grpc::ChannelArguments()));
  EXPECT_THAT(hats_orchestrator_client.GetHpkeKey(),
              IsOkAndHolds(StrEq(kTestKey)));
}

TEST(HatsOrchestratorClient, Error) {
  TestHatsOrchestratorService test_service(/*return_error=*/true);
  std::unique_ptr<grpc::Server> server =
      grpc::ServerBuilder().RegisterService(&test_service).BuildAndStart();
  HatsOrchestratorClient hats_orchestrator_client(
      server->InProcessChannel(grpc::ChannelArguments()));
  EXPECT_THAT(hats_orchestrator_client.GetHpkeKey(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Invalid argument")));
}

}  // namespace
}  // namespace privacy_sandbox::client
