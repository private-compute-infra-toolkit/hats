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

#include "client/launcher/launcher-server.h"

#include <fcntl.h>

#include <cstdint>
#include <exception>
#include <fstream>
#include <memory>
#include <string>
#include <utility>

#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "client/launcher/certificates.h"
#include "client/proto/launcher.grpc.pb.h"
#include "external/oak/proto/containers/interfaces.pb.h"
#include "google/protobuf/empty.pb.h"
#include "grpcpp/channel.h"
#include "grpcpp/server.h"
#include "grpcpp/server_builder.h"
#include "grpcpp/support/status.h"
#include "grpcpp/support/sync_stream.h"
#include "tvs/proto/tvs_messages.pb.h"

namespace privacy_sandbox::client {

namespace {
grpc::Status StreamFile(
    const grpc::ServerContext& context, absl::string_view image_path,
    const size_t chunk_size,
    grpc::ServerWriter<oak::containers::GetImageResponse>& writer) {
  std::ifstream input_stream(image_path.data(), std::ifstream::binary);
  if (!input_stream.is_open()) {
    return grpc::Status(grpc::StatusCode::NOT_FOUND,
                        absl::StrFormat("failed to open image path %s"));
  }

  while (!input_stream.eof()) {
    // Client cancellation or deadline exceeded.
    if (context.IsCancelled()) {
      return grpc::Status::CANCELLED;
    }
    oak::containers::GetImageResponse response;
    std::string buffer;
    buffer.resize(chunk_size);
    input_stream.read(buffer.data(), buffer.size());
    buffer.resize(input_stream.gcount());
    *response.mutable_image_chunk() = std::move(buffer);
    writer.Write(response);
  }

  // File stream error during file reading.
  if (input_stream.bad()) {
    return grpc::Status(grpc::StatusCode::UNKNOWN, "fail to read file stream");
  }
  input_stream.close();
  return grpc::Status::OK;
}
}  // namespace

LauncherOakServer::LauncherOakServer(absl::string_view oak_system_image,
                                     absl::string_view container_bundle,
                                     size_t chunk_size)
    : oak_system_image_(oak_system_image),
      container_bundle_(container_bundle),
      chunk_size_(chunk_size) {}

grpc::Status LauncherOakServer::GetOakSystemImage(
    grpc::ServerContext* context, const google::protobuf::Empty* request,
    grpc::ServerWriter<oak::containers::GetImageResponse>* writer) {
  return StreamFile(*context, oak_system_image_, chunk_size_, *writer);
}

grpc::Status LauncherOakServer::GetContainerBundle(
    grpc::ServerContext* context, const google::protobuf::Empty* request,
    grpc::ServerWriter<oak::containers::GetImageResponse>* writer) {
  return StreamFile(*context, container_bundle_, chunk_size_, *writer);
}

grpc::Status LauncherOakServer::GetApplicationConfig(
    grpc::ServerContext* context, const google::protobuf::Empty* request,
    oak::containers::GetApplicationConfigResponse* response) {
  return grpc::Status(grpc::StatusCode::UNIMPLEMENTED, "");
}

grpc::Status LauncherOakServer::GetEndorsements(
    grpc::ServerContext* context, const google::protobuf::Empty* request,
    oak::attestation::v1::Endorsements* response) {
  return grpc::Status(grpc::StatusCode::UNIMPLEMENTED, "");
}

grpc::Status LauncherOakServer::SendAttestationEvidence(
    grpc::ServerContext* context,
    const oak::containers::SendAttestationEvidenceRequest* request,
    google::protobuf::Empty* response) {
  return grpc::Status(grpc::StatusCode::UNIMPLEMENTED, "");
}

grpc::Status LauncherOakServer::NotifyAppReady(
    grpc::ServerContext* context, const google::protobuf::Empty* request,
    google::protobuf::Empty* response) {
  return grpc::Status(grpc::StatusCode::UNIMPLEMENTED, "");
}

LauncherServer::LauncherServer(absl::string_view tvs_authentication_key,
                               std::shared_ptr<grpc::Channel> channel)
    : tvs_authentication_key_(tvs_authentication_key),
      stub_(tvs::TeeVerificationService::NewStub(channel)) {}

grpc::Status LauncherServer::VerifyReport(
    grpc::ServerContext* context,
    grpc::ServerReaderWriter<tvs::OpaqueMessage, tvs::OpaqueMessage>* stream) {
  auto remote_context = std::make_unique<grpc::ClientContext>();
  std::unique_ptr<
      grpc::ClientReaderWriter<tvs::OpaqueMessage, tvs::OpaqueMessage>>
      remote_stream = stub_->VerifyReport(remote_context.get());
  tvs::OpaqueMessage opaque_message;
  while (stream->Read((&opaque_message))) {
    if (!remote_stream->Write(opaque_message)) {
      return grpc::Status(
          grpc::StatusCode::UNKNOWN,
          absl::StrCat("Failed to write to stream. ",
                       remote_stream->Finish().error_message()));
    }
    if (!remote_stream->Read(&opaque_message)) {
      return grpc::Status(
          grpc::StatusCode::UNKNOWN,
          absl::StrCat("Failed to read from stream. ",
                       remote_stream->Finish().error_message()));
    }
    // Send the message back to the client.
    if (!stream->Write(opaque_message)) {
      return grpc::Status(grpc::StatusCode::UNKNOWN,
                          "Failed to write message to stream. ");
    }
  }
  return grpc::Status::OK;
}

grpc::Status LauncherServer::FetchOrchestratorMetadata(
    grpc::ServerContext* context, const google::protobuf::Empty* request,
    privacy_sandbox::client::FetchOrchestratorMetadataResponse* reply) {
  absl::StatusOr<std::string> certificate = DownloadCertificate();
  if (!certificate.ok()) {
    return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION,
                        std::string(certificate.status().message()));
  }
  reply->set_tee_certificate(*std::move(certificate));
  reply->set_tvs_authentication_key(tvs_authentication_key_);
  return grpc::Status::OK;
}
}  // namespace privacy_sandbox::client
