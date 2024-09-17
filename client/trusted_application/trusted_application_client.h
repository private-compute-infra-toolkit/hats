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

#ifndef TRUSTED_APPLICATION_CLIENT_H_
#define TRUSTED_APPLICATION_CLIENT_H_

#include <memory>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "client/proto/trusted_service.grpc.pb.h"
#include "client/proto/trusted_service.pb.h"
#include "crypto/secret-data.h"
#include "grpcpp/channel.h"
#include "grpcpp/create_channel.h"

namespace privacy_sandbox::client {

constexpr absl::string_view kTestMessage =
    "Hello from inside the trusted application!\n";

// Client to the trusted application to be used by the 'client' to send
// encrypted requests and receive decrypted responses.
class TrustedApplicationClient final {
 public:
  TrustedApplicationClient(absl::string_view private_key, int8_t key_id);
  TrustedApplicationClient(absl::string_view address,
                           absl::string_view private_key, int8_t key_id);

  absl::StatusOr<DecryptedResponse> SendEcho() const;
  absl::StatusOr<DecryptedResponse> SendEcho(
      absl::string_view to_encrypt) const;

 private:
  std::unique_ptr<TrustedService::Stub> trusted_service_stub_;
  crypto::SecretData private_key_;
  int8_t key_id_;
};

}  // namespace privacy_sandbox::client
#endif  // TRUSTED_APPLICATION_CLIENT_H_
