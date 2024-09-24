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

#ifndef HATS_CLIENT_LAUNCHER_LAUNCHER_SERVER_
#define HATS_CLIENT_LAUNCHER_LAUNCHER_SERVER_

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "absl/strings/string_view.h"
#include "client/proto/launcher.grpc.pb.h"
#include "client/proto/launcher.pb.h"
#include "external/oak/proto/containers/interfaces.grpc.pb.h"
#include "external/oak/proto/containers/interfaces.pb.h"
#include "google/protobuf/empty.pb.h"
#include "grpcpp/support/status.h"
#include "grpcpp/support/sync_stream.h"
#include "tvs/proto/tvs.grpc.pb.h"
#include "tvs/proto/tvs_messages.pb.h"

namespace privacy_sandbox::client {

class LauncherOakServer final : public oak::containers::Launcher::Service {
 public:
  LauncherOakServer(absl::string_view oak_system_image,
                    absl::string_view container_bundle, size_t chunk_size);

  grpc::Status GetOakSystemImage(
      grpc::ServerContext* context, const google::protobuf::Empty* request,
      grpc::ServerWriter<oak::containers::GetImageResponse>* writer) override;
  // Provides orchestrator with the trusted container image.
  grpc::Status GetContainerBundle(
      grpc::ServerContext* context, const google::protobuf::Empty* request,
      grpc::ServerWriter<oak::containers::GetImageResponse>* writer) override;
  // This method is used by the orchestrator to load and measure the trusted
  // application config. The orchestrator will later, separately expose this
  // config to the application.
  grpc::Status GetApplicationConfig(
      grpc::ServerContext* context, const google::protobuf::Empty* request,
      oak::containers::GetApplicationConfigResponse* response) override;
  // Provides the orchestrator with the endorsements of the trusted application
  // and the container.
  grpc::Status GetEndorsements(
      grpc::ServerContext* context, const google::protobuf::Empty* request,
      oak::attestation::v1::Endorsements* response) override;
  // Sends Attestation Evidence containing the Attestation Report with
  // corresponding measurements and public keys to the Launcher. This API is
  // called exactly once after the Attestation Evidence is generated. Calling
  // this API a second time will result in an error.
  grpc::Status SendAttestationEvidence(
      grpc::ServerContext* context,
      const oak::containers::SendAttestationEvidenceRequest* request,
      google::protobuf::Empty* response) override;
  // Notifies the launcher that the trusted app is ready to serve requests and
  // listening on the pre-arranged port (8080).
  grpc::Status NotifyAppReady(grpc::ServerContext* context,
                              const google::protobuf::Empty* request,
                              google::protobuf::Empty* response) override;

 private:
  const std::string oak_system_image_;
  const std::string container_bundle_;
  const size_t chunk_size_;
};

class LauncherServer final
    : public privacy_sandbox::client::LauncherService::Service {
 public:
  // tvs_authentication_key is in bytes format.
  LauncherServer(
      absl::string_view tvs_authentication_key,
      const PrivateKeyWrappingKeys& private_key_wrapping_keys,
      const std::unordered_map<int64_t, std::shared_ptr<grpc::Channel>>&
          channel_map,
      bool fetch_tee_certificate);

  // Pipes messages between the client and the server.
  // This used to proxy communication between the orchestrator and Tvs.
  grpc::Status VerifyReport(
      grpc::ServerContext* context,
      grpc::ServerReaderWriter<tvs::OpaqueMessage, ForwardingTvsMessage>*
          stream) override;

  grpc::Status FetchOrchestratorMetadata(
      grpc::ServerContext* context, const google::protobuf::Empty* request,
      privacy_sandbox::client::FetchOrchestratorMetadataResponse* reply)
      override;

 private:
  const std::string tvs_authentication_key_;
  std::unordered_map<int64_t,
                     std::shared_ptr<tvs::TeeVerificationService::Stub>>
      stubs_;
  const PrivateKeyWrappingKeys private_key_wrapping_keys_;
  const bool fetch_tee_certificate_;
};

}  // namespace privacy_sandbox::client

#endif  // HATS_CLIENT_LAUNCHER_LAUNCHER_SERVER_
