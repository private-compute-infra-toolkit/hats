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
#include "tvs/standalone_server/tvs-service.h"

ABSL_FLAG(int, port, -1, "Port TVS server listens to.");
ABSL_FLAG(bool, enable_policy_signature, false,
          "Whether to check signatures on policies");
ABSL_FLAG(bool, accept_insecure_policies, false,
          "Whether to accept policies allowing evidence from insecure "
          "hardware. Enable for testing only.");
ABSL_FLAG(bool, enable_dynamic_policy_fetching, false,
          "Whether or not to fetch policies from storage for every request. "
          "Instead of pre-fetching policies once during boot time.  Note that "
          "this option might cause the performance to degrade.");

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

absl::StatusOr<privacy_sandbox::tvs::TvsService::Options>
TvsServiceOptionsFromFlags() {
  privacy_sandbox::tvs::TvsService::Options options;
  options.key_fetcher = privacy_sandbox::key_manager::KeyFetcher::Create();
  HATS_ASSIGN_OR_RETURN(
      std::unique_ptr<privacy_sandbox::tvs::PolicyFetcher> policy_fetcher,
      privacy_sandbox::tvs::PolicyFetcher::Create(),
      _.PrependWith("Failed to create a policy fetcher: "));
  options.enable_policy_signature =
      absl::GetFlag(FLAGS_enable_policy_signature);
  options.accept_insecure_policies =
      absl::GetFlag(FLAGS_accept_insecure_policies);
  if (absl::GetFlag(FLAGS_enable_dynamic_policy_fetching)) {
    options.policy_fetcher = std::move(policy_fetcher);
  } else {
    HATS_ASSIGN_OR_RETURN(
        privacy_sandbox::tvs::AppraisalPolicies appraisal_policies,
        policy_fetcher->GetLatestNPolicies(/*n=*/10),
        _.PrependWith("Failed to get appraisal policies: "));
    options.appraisal_policies = std::move(appraisal_policies);
  }
  return options;
}

}  // namespace

int main(int argc, char* argv[]) {
  absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();

  HATS_ASSIGN_OR_RETURN(
      int port, GetPort(),
      _.PrependWith("Cannot get server port: ").LogErrorAndExit());

  if (absl::GetFlag(FLAGS_accept_insecure_policies)) {
    LOG(WARNING) << "The server is accepting insecure policies. This should be "
                    "enabled for testing only.";
  }

  HATS_ASSIGN_OR_RETURN(
      privacy_sandbox::tvs::TvsService::Options tvs_service_options,
      TvsServiceOptionsFromFlags(), _.LogErrorAndExit());

  HATS_ASSIGN_OR_RETURN(
      std::unique_ptr<privacy_sandbox::tvs::TvsService> tvs_service,
      privacy_sandbox::tvs::TvsService::Create(std::move(tvs_service_options)),
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
