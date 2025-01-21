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

#include <cstdlib>
#include <memory>
#include <string>
#include <utility>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/flags.h"  // IWYU pragma: keep
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "absl/status/statusor.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "grpcpp/security/server_credentials.h"
#include "grpcpp/server.h"
#include "grpcpp/server_builder.h"
#include "key_manager/key-fetcher.h"
#include "status_macro/status_macros.h"
#include "tvs/appraisal_policies/policy-fetcher.h"
#include "tvs/proto/appraisal_policies.pb.h"
#include "tvs/untrusted_tvs/tvs-service.h"

ABSL_FLAG(int, port, -1, "Port TVS server listens to.");
ABSL_FLAG(std::string, vmm_binary, "", "Path to the VMM binary (qemu)");
ABSL_FLAG(std::string, bios_binary, "", "Path to the bios binary (stage0)");
ABSL_FLAG(std::string, kernel, "",
          "Path to the kernel binary (Oak restricted kernel)");
ABSL_FLAG(std::string, initrd, "",
          "Path to the initrd binary (Oak Orchestrator)");
ABSL_FLAG(std::string, app_binary, "",
          "Path to the trusted application binary (TVS enclave app)");
ABSL_FLAG(std::string, memory_size, "20G",
          "Size of the memory to give the virtual machine running TVS enclave");

namespace {

absl::StatusOr<int> GetPort() {
  int port = absl::GetFlag(FLAGS_port);
  if (port != -1) {
    return port;
  }
  // if port is -1, then take try environment variable.
  char* port_str = std::getenv("PORT");
  if (port_str == nullptr) {
    return absl::FailedPreconditionError(
        "Server port must be specified by flag or PORT environment variable");
  }

  if (!absl::SimpleAtoi(port_str, &port)) {
    return absl::InvalidArgumentError(
        absl::StrCat("Cannot convert $PORT '", port_str, "' to integer"));
  }
  return port;
}

}  // namespace

int main(int argc, char* argv[]) {
  absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();

  std::unique_ptr<privacy_sandbox::key_manager::KeyFetcher> key_fetcher =
      privacy_sandbox::key_manager::KeyFetcher::Create();
  HATS_ASSIGN_OR_RETURN(
      int port, GetPort(),
      _.PrependWith("Cannot get server port: ").LogErrorAndExit());

  HATS_ASSIGN_OR_RETURN(
      std::unique_ptr<privacy_sandbox::tvs::PolicyFetcher> policy_fetcher,
      privacy_sandbox::tvs::PolicyFetcher::Create(),
      _.PrependWith("Failed to create a policy fetcher: ").LogErrorAndExit());

  HATS_ASSIGN_OR_RETURN(
      privacy_sandbox::tvs::AppraisalPolicies appraisal_policies,
      policy_fetcher->GetLatestNPolicies(/*n=*/30),
      _.PrependWith("Failed to get appraisal policies: ").LogErrorAndExit());

  HATS_ASSIGN_OR_RETURN(
      std::unique_ptr<privacy_sandbox::tvs::TvsService> tvs_service,
      privacy_sandbox::tvs::TvsService::Create({
          .key_fetcher = std::move(key_fetcher),
          .appraisal_policies = std::move(appraisal_policies),
          .vmm_binary = absl::GetFlag(FLAGS_vmm_binary),
          .bios_binary = absl::GetFlag(FLAGS_bios_binary),
          .kernel = absl::GetFlag(FLAGS_kernel),
          .initrd = absl::GetFlag(FLAGS_initrd),
          .app_binary = absl::GetFlag(FLAGS_app_binary),
          .memory_size = absl::GetFlag(FLAGS_memory_size),
      }),
      _.PrependWith("Failed to create TVS server: ").LogErrorAndExit());

  LOG(INFO) << "Starting TVS server on port " << port;
  const std::string server_address = absl::StrCat("0.0.0.0:", port);
  std::unique_ptr<grpc::Server> server =
      grpc::ServerBuilder()
          .AddListeningPort(server_address, grpc::InsecureServerCredentials())
          .RegisterService(tvs_service.get())
          .BuildAndStart();
  LOG(INFO) << "Server listening on " << server_address;
  server->Wait();

  return 0;
}
