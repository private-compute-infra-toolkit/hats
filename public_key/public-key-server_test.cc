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

#include "public_key/public-key-server.h"

#include <memory>
#include <string>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "gmock/gmock.h"
#include "google/cloud/storage/testing/mock_client.h"
#include "grpcpp/client_context.h"
#include "grpcpp/server.h"
#include "grpcpp/server_builder.h"
#include "grpcpp/support/channel_arguments.h"
#include "gtest/gtest.h"
#include "key_manager/public-key-fetcher.h"
#include "src/google/protobuf/test_textproto.h"
#include "status_macro/status_test_macros.h"

namespace privacy_sandbox::public_key_service {
namespace {
namespace gcs = ::google::cloud::storage;
using ::google::cloud::storage::internal::CreateResumableUploadResponse;
using ::google::cloud::storage::internal::QueryResumableUploadResponse;
using ::google::protobuf::EqualsProto;
using ::privacy_sandbox::key_manager::PerOriginPublicKey;
using ::privacy_sandbox::key_manager::PublicKeyFetcher;
using ::testing::AllOf;
using ::testing::HasSubstr;
using ::testing::Property;
using ::testing::Return;

class FakePublicKeyFetcher : public PublicKeyFetcher {
 public:
  FakePublicKeyFetcher(int64_t user_key_id, absl::string_view user_public_key,
                       absl::string_view user_origin)
      : user_key_id_(user_key_id),
        user_public_key_(user_public_key),
        user_origin_(user_origin) {}

  absl::StatusOr<std::vector<PerOriginPublicKey>> GetLatestPublicKeys()
      override {
    return std::vector<PerOriginPublicKey>({PerOriginPublicKey{
        .key_id = user_key_id_,
        .public_key = user_public_key_,
        .origin = user_origin_,
    }});
  }

 private:
  int64_t user_key_id_;
  const std::string user_public_key_;
  const std::string user_origin_;
};

constexpr absl::string_view kExpectedPublicKeys = R"pb(
  public_keys {
    key_id: "4000000000000000"
    public_key: "YgtDEwF/OkbyjDwQhJAQnZ9+H2671K8wdlAMeMFCpQs="
    origin: "http://example.com"
    execution_environment: EXECUTION_ENVIRONMENT_ONPREM
  }
)pb";

TEST(PublicKeyServer, ListPublicKeys) {
  std::shared_ptr<gcs::testing::MockClient> mock =
      std::make_shared<gcs::testing::MockClient>();
  PublicKeyServer public_key_server(
      {
          .port = -1,  // Not used in test.
          .gcp_cloud_bucket_name = "example",
      },
      absl::WrapUnique(new FakePublicKeyFetcher(
          /*user_key_id=*/4611686018427387904,
          /*user_public_key=*/
          "620b4313017f3a46f28c3c108490109d9f7e1f6ebbd4af3076500c78c142a50b",
          /*user_origin=*/"http://example.com")),
      gcs::testing::UndecoratedClientFromMock(mock));
  std::unique_ptr<grpc::Server> grpc_server =
      grpc::ServerBuilder().RegisterService(&public_key_server).BuildAndStart();

  std::unique_ptr<PublicKeyService::Stub> client = PublicKeyService::NewStub(
      grpc_server->InProcessChannel(grpc::ChannelArguments()));
  grpc::ClientContext context;
  google::protobuf::Empty request;
  ListPublicKeysResponse response;
  HATS_EXPECT_OK_GRPC(client->ListPublicKeys(&context, request, &response));
  EXPECT_THAT(response, EqualsProto(kExpectedPublicKeys));
}

TEST(PublicKeyServer, ListPublicKeysFailure) {
  std::shared_ptr<gcs::testing::MockClient> mock =
      std::make_shared<gcs::testing::MockClient>();
  PublicKeyServer public_key_server(
      {
          .port = -1,  // Not used in test.
          .gcp_cloud_bucket_name = "example",
      },
      absl::WrapUnique(new FakePublicKeyFetcher(
          /*user_key_id=*/4611686018427387904,
          /*user_public_key=*/
          "zcxzcx",  // invalid public key
          /*user_origin=*/"http://example.com")),
      gcs::testing::UndecoratedClientFromMock(mock));
  std::unique_ptr<grpc::Server> grpc_server =
      grpc::ServerBuilder().RegisterService(&public_key_server).BuildAndStart();

  std::unique_ptr<PublicKeyService::Stub> client = PublicKeyService::NewStub(
      grpc_server->InProcessChannel(grpc::ChannelArguments()));
  grpc::ClientContext context;
  google::protobuf::Empty request;
  ListPublicKeysResponse response;
  HATS_EXPECT_STATUS_GRPC(client->ListPublicKeys(&context, request, &response),
                          absl::StatusCode::kInternal);
}

TEST(PublicKeyServer, UpdateCloudBucket) {
  std::shared_ptr<gcs::testing::MockClient> mock =
      std::make_shared<gcs::testing::MockClient>();
  gcs::ObjectMetadata expected_metadata;
  EXPECT_CALL(*mock, CreateResumableUpload)
      .WillOnce(Return(CreateResumableUploadResponse{"test-only-upload-id"}));
  EXPECT_CALL(*mock, UploadChunk)
      .WillOnce(Return(QueryResumableUploadResponse{
          /*.committed_size=*/absl::nullopt,
          /*.object_metadata=*/expected_metadata}));

  PublicKeyServer public_key_server(
      {
          .port = -1,  // Not used in test.
          .gcp_cloud_bucket_name = "example",
      },
      absl::WrapUnique(new FakePublicKeyFetcher(
          /*user_key_id=*/4611686018427387904,
          /*user_public_key=*/
          "620b4313017f3a46f28c3c108490109d9f7e1f6ebbd4af3076500c78c142a50b",
          /*user_origin=*/"http://example.com")),
      gcs::testing::UndecoratedClientFromMock(mock));
  std::unique_ptr<grpc::Server> grpc_server =
      grpc::ServerBuilder().RegisterService(&public_key_server).BuildAndStart();

  std::unique_ptr<PublicKeyService::Stub> client = PublicKeyService::NewStub(
      grpc_server->InProcessChannel(grpc::ChannelArguments()));
  grpc::ClientContext context;
  google::protobuf::Empty request;
  google::protobuf::Empty response;
  HATS_EXPECT_OK_GRPC(client->UpdateCloudBucket(&context, request, &response));
}

TEST(PublicKeyServer, UpdateCloudBucketFailure) {
  std::shared_ptr<gcs::testing::MockClient> mock =
      std::make_shared<gcs::testing::MockClient>();
  gcs::ObjectMetadata expected_metadata;
  EXPECT_CALL(*mock, CreateResumableUpload)
      .WillOnce(Return(CreateResumableUploadResponse{"test-only-upload-id"}));
  EXPECT_CALL(*mock, UploadChunk)
      .WillOnce(Return(
          google::cloud::Status(google::cloud::StatusCode::kInternal, "")));

  PublicKeyServer public_key_server(
      {
          .port = -1,  // Not used in test.
          .gcp_cloud_bucket_name = "example",
      },
      absl::WrapUnique(new FakePublicKeyFetcher(
          /*user_key_id=*/4611686018427387904,
          /*user_public_key=*/
          "620b4313017f3a46f28c3c108490109d9f7e1f6ebbd4af3076500c78c142a50b",
          /*user_origin=*/"http://example.com")),
      gcs::testing::UndecoratedClientFromMock(mock));
  std::unique_ptr<grpc::Server> grpc_server =
      grpc::ServerBuilder().RegisterService(&public_key_server).BuildAndStart();

  std::unique_ptr<PublicKeyService::Stub> client = PublicKeyService::NewStub(
      grpc_server->InProcessChannel(grpc::ChannelArguments()));
  grpc::ClientContext context;
  google::protobuf::Empty request;
  google::protobuf::Empty response;
  HATS_EXPECT_STATUS_GRPC(
      client->UpdateCloudBucket(&context, request, &response),
      absl::StatusCode::kInternal);
}

}  // namespace
}  // namespace privacy_sandbox::public_key_service
