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

#include <fstream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "gmock/gmock.h"
#include "google/cloud/storage/testing/mock_client.h"
#include "grpcpp/client_context.h"
#include "grpcpp/server.h"
#include "grpcpp/server_builder.h"
#include "grpcpp/support/channel_arguments.h"
#include "grpcpp/support/status.h"
#include "gtest/gtest.h"
#include "key_manager/public-key-fetcher.h"
#include "src/google/protobuf/test_textproto.h"
#include "tools/cpp/runfiles/runfiles.h"

#include "httplib.h"
namespace privacy_sandbox::public_key_service {
namespace {
namespace gcs = ::google::cloud::storage;
using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
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

constexpr absl::string_view kAwsHttpResponse = R"json(
{
  "keys": [{
    "id": "1200000000000000",
    "key": "6IfKJbduQ5R3LKuuATm7/Sv47tkF13MzYnFw7Jrkmhw\u003d"
  }, {
    "id": "5200000000000000",
    "key": "85CzRflG0AO6QwSG9zbFADPrm9f8nDhj3PI0Cg6vjQw\u003d"
  }, {
    "id": "6200000000000000",
    "key": "Hb4iIzuLHl994lUjQhAkts6MEjhgJ6z3iQp0PB7Q4Q4\u003d"
  }, {
    "id": "9200000000000000",
    "key": "LOv/7siRJhhSTSqQ470Q1RwkAb2W9aj+B44NrHPkfRA\u003d"
  }, {
    "id": "E200000000000000",
    "key": "beTaiDpJwAtmQe/01fJiBxDFsumBUSgQpfnuKc+QkiU\u003d"
  }]
}
)json";

constexpr absl::string_view kGcpHttpResponse = R"json(
{
  "keys": [{
    "id": "0080000000000000",
    "key": "ZqXg+fzqNDWokzKpe6FqOukdffbwOSZYv32Ut2N38Wo\u003d"
  }, {
    "id": "4080000000000000",
    "key": "laZrDyYU39ZdMhYx/jC9A0RgxOBmfCZAqje/9sdJEHk\u003d"
  }, {
    "id": "7F00000000000000",
    "key": "WOBkDqGmKGRScDbq1Un0AyMVv8Gnmh39iiK9RBw4Ak0\u003d"
  }, {
    "id": "8080000000000000",
    "key": "QKnL2vfKi9NkfGxpJbTcQwsygcxrM3BInJ3FHIYN3xI\u003d"
  }, {
    "id": "FF00000000000000",
    "key": "rPA5VWHfMzsJq+40adr+iBIHCc7GxejUqjnyakeFUHU\u003d"
  }]
}
)json";

constexpr absl::string_view kExpectedPublicKeys = R"pb(
  public_keys {
    key_id: "1200000000000000"
    public_key: "6IfKJbduQ5R3LKuuATm7/Sv47tkF13MzYnFw7Jrkmhw="
    execution_environment: EXECUTION_ENVIRONMENT_AWS
  }
  public_keys {
    key_id: "5200000000000000"
    public_key: "85CzRflG0AO6QwSG9zbFADPrm9f8nDhj3PI0Cg6vjQw="
    execution_environment: EXECUTION_ENVIRONMENT_AWS
  }
  public_keys {
    key_id: "6200000000000000"
    public_key: "Hb4iIzuLHl994lUjQhAkts6MEjhgJ6z3iQp0PB7Q4Q4="
    execution_environment: EXECUTION_ENVIRONMENT_AWS
  }
  public_keys {
    key_id: "9200000000000000"
    public_key: "LOv/7siRJhhSTSqQ470Q1RwkAb2W9aj+B44NrHPkfRA="
    execution_environment: EXECUTION_ENVIRONMENT_AWS
  }
  public_keys {
    key_id: "E200000000000000"
    public_key: "beTaiDpJwAtmQe/01fJiBxDFsumBUSgQpfnuKc+QkiU="
    execution_environment: EXECUTION_ENVIRONMENT_AWS
  }
  public_keys {
    key_id: "0080000000000000"
    public_key: "ZqXg+fzqNDWokzKpe6FqOukdffbwOSZYv32Ut2N38Wo="
    execution_environment: EXECUTION_ENVIRONMENT_GCP
  }
  public_keys {
    key_id: "4080000000000000"
    public_key: "laZrDyYU39ZdMhYx/jC9A0RgxOBmfCZAqje/9sdJEHk="
    execution_environment: EXECUTION_ENVIRONMENT_GCP
  }
  public_keys {
    key_id: "7F00000000000000"
    public_key: "WOBkDqGmKGRScDbq1Un0AyMVv8Gnmh39iiK9RBw4Ak0="
    execution_environment: EXECUTION_ENVIRONMENT_GCP
  }
  public_keys {
    key_id: "8080000000000000"
    public_key: "QKnL2vfKi9NkfGxpJbTcQwsygcxrM3BInJ3FHIYN3xI="
    execution_environment: EXECUTION_ENVIRONMENT_GCP
  }
  public_keys {
    key_id: "FF00000000000000"
    public_key: "rPA5VWHfMzsJq+40adr+iBIHCc7GxejUqjnyakeFUHU="
    execution_environment: EXECUTION_ENVIRONMENT_GCP
  }
  public_keys {
    key_id: "4000000000000000"
    public_key: "YgtDEwF/OkbyjDwQhJAQnZ9+H2671K8wdlAMeMFCpQs="
    adtech_origin: "http://example.com"
    execution_environment: EXECUTION_ENVIRONMENT_ONPREM
  }
)pb";

TEST(PublicKeyServer, ListPublicKeys) {
  // Start fake http server to handle key endpoints.
  httplib::Server server;
  server.Get("/aws",
             [&](const httplib::Request& request, httplib::Response& response) {
               if (request.method == "GET" && request.path == "/aws") {
                 response.set_content(kAwsHttpResponse.data(),
                                      "application/json;charset=iso-8859-1");
               }
             });
  server.Get("/gcp",
             [&](const httplib::Request& request, httplib::Response& response) {
               if (request.method == "GET" && request.path == "/gcp") {
                 response.set_content(kGcpHttpResponse.data(),
                                      "application/json;charset=iso-8859-1");
               }
             });
  int port = server.bind_to_any_port("0.0.0.0");
  std::thread server_thread([&] { server.listen_after_bind(); });
  // Wait for the server to start before sending requests otherwise we might
  // deadlock.
  server.wait_until_ready();
  std::shared_ptr<gcs::testing::MockClient> mock =
      std::make_shared<gcs::testing::MockClient>();
  PublicKeyServer public_key_server(
      {
          .port = -1,  // Not used in test.
          .aws_key_endpoint = absl::StrCat("localhost:", port, "/aws"),
          .gcp_key_endpoint = absl::StrCat("localhost:", port, "/gcp"),
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
  grpc::Status status = client->ListPublicKeys(&context, request, &response);
  EXPECT_TRUE(status.ok());
  EXPECT_THAT(response, EqualsProto(kExpectedPublicKeys));
  server.stop();
  server_thread.join();
}

TEST(PublicKeyServer, ListPublicKeysFailure) {
  // Start fake http server to handle key endpoints.
  httplib::Server server;
  // invalid aws response results in failure.
  server.Get("/aws", [&](const httplib::Request& request,
                         httplib::Response& response) {
    if (request.method == "GET" && request.path == "/aws") {
      response.set_content("};", "application/json;charset=iso-8859-1");
    }
  });
  server.Get("/gcp",
             [&](const httplib::Request& request, httplib::Response& response) {
               if (request.method == "GET" && request.path == "/gcp") {
                 response.set_content(kGcpHttpResponse.data(),
                                      "application/json;charset=iso-8859-1");
               }
             });
  int port = server.bind_to_any_port("0.0.0.0");
  std::thread server_thread([&] { server.listen_after_bind(); });
  // Wait for the server to start before sending requests otherwise we might
  // deadlock.
  server.wait_until_ready();
  std::shared_ptr<gcs::testing::MockClient> mock =
      std::make_shared<gcs::testing::MockClient>();
  PublicKeyServer public_key_server(
      {
          .port = -1,  // Not used in test.
          .aws_key_endpoint = absl::StrCat("localhost:", port, "/aws"),
          .gcp_key_endpoint = absl::StrCat("localhost:", port, "/gcp"),
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
  grpc::Status status = client->ListPublicKeys(&context, request, &response);
  EXPECT_TRUE(!status.ok());
  server.stop();
  server_thread.join();
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

  httplib::Server server;
  server.Get("/aws",
             [&](const httplib::Request& request, httplib::Response& response) {
               if (request.method == "GET" && request.path == "/aws") {
                 response.set_content(kAwsHttpResponse.data(),
                                      "application/json;charset=iso-8859-1");
               }
             });
  server.Get("/gcp",
             [&](const httplib::Request& request, httplib::Response& response) {
               if (request.method == "GET" && request.path == "/gcp") {
                 response.set_content(kGcpHttpResponse.data(),
                                      "application/json;charset=iso-8859-1");
               }
             });
  int port = server.bind_to_any_port("0.0.0.0");
  std::thread server_thread([&] { server.listen_after_bind(); });
  // Wait for the server to start before sending requests otherwise we might
  // deadlock.
  server.wait_until_ready();
  PublicKeyServer public_key_server(
      {
          .port = -1,  // Not used in test.
          .aws_key_endpoint = absl::StrCat("localhost:", port, "/aws"),
          .gcp_key_endpoint = absl::StrCat("localhost:", port, "/gcp"),
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
  grpc::Status status = client->UpdateCloudBucket(&context, request, &response);
  EXPECT_TRUE(status.ok());
  server.stop();
  server_thread.join();
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

  httplib::Server server;
  server.Get("/aws",
             [&](const httplib::Request& request, httplib::Response& response) {
               if (request.method == "GET" && request.path == "/aws") {
                 response.set_content(kAwsHttpResponse.data(),
                                      "application/json;charset=iso-8859-1");
               }
             });
  server.Get("/gcp",
             [&](const httplib::Request& request, httplib::Response& response) {
               if (request.method == "GET" && request.path == "/gcp") {
                 response.set_content(kGcpHttpResponse.data(),
                                      "application/json;charset=iso-8859-1");
               }
             });
  int port = server.bind_to_any_port("0.0.0.0");
  std::thread server_thread([&] { server.listen_after_bind(); });
  // Wait for the server to start before sending requests otherwise we might
  // deadlock.
  server.wait_until_ready();
  PublicKeyServer public_key_server(
      {
          .port = -1,  // Not used in test.
          .aws_key_endpoint = absl::StrCat("localhost:", port, "/aws"),
          .gcp_key_endpoint = absl::StrCat("localhost:", port, "/gcp"),
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
  grpc::Status status = client->UpdateCloudBucket(&context, request, &response);
  EXPECT_TRUE(!status.ok());
  server.stop();
  server_thread.join();
}

}  // namespace
}  // namespace privacy_sandbox::public_key_service
