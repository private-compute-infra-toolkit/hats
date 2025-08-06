// Copyright 2025 Google LLC.
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

#include <iostream>
#include <string>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/flags.h"  // IWYU pragma: keep
#include "absl/strings/escaping.h"
#include "client/trusted_application/client/trusted_application_client.h"

ABSL_FLAG(std::string, app_key,
          "67ff77cf4cf44dde9591555ac55402176d5a161880fede6badbf9e2202c2363d",
          "AES-256 application key for encrypting the payload");
ABSL_FLAG(std::string, address, "localhost:8000",
          "address used for making grpc calls to this service");
ABSL_FLAG(std::string, key_id, "1", "key_id to retrieve from orchestrator");
ABSL_FLAG(std::string, echo_message, std::string(pcit::client::kTestMessage),
          "message to echo back from trusted app");

int main(int argc, char* argv[]) {
  absl::ParseCommandLine(argc, argv);
  std::string key;
  if (!absl::HexStringToBytes(absl::GetFlag(FLAGS_app_key), &key)) {
    std::cerr << "Application key must be a hex string" << std::endl;
    return 1;
  }
  pcit::client::TrustedApplicationClient app_client(
      absl::GetFlag(FLAGS_address), key, absl::GetFlag(FLAGS_key_id));
  absl::StatusOr<pcit::client::DecryptedResponse> response =
      app_client.SendEcho(absl::GetFlag(FLAGS_echo_message));
  if (!response.ok()) {
    std::cerr << "Failed to send echo request to trusted application: "
              << response.status() << std::endl;
    return 1;
  }
  std::cout << response->response();
}
