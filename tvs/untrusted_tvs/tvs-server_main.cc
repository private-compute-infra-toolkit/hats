#include <cstdlib>
#include <fstream>
#include <optional>
#include <string>
#include <utility>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "google/protobuf/io/zero_copy_stream_impl.h"
#include "google/protobuf/text_format.h"
#include "proto/attestation/reference_value.pb.h"
#include "tvs/untrusted_tvs/tvs-server.h"

ABSL_FLAG(int, port, -1, "Port TVS server listens to.");
// TODO(alwabel): implement a better key provisioning.
ABSL_FLAG(std::string, tvs_private_key, "",
          "Private key for NK-Noise handshake protocol.");
ABSL_FLAG(std::string, appraisal_policy_file, "",
          "Policy that defines acceptable evidence.");

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

  const std::string appraisal_policy_file =
      absl::GetFlag(FLAGS_appraisal_policy_file);
  if (appraisal_policy_file.empty()) {
    LOG(ERROR) << "--appraisal_policy_file cannot be empty.";
    return 1;
  }
  std::ifstream if_stream(appraisal_policy_file);
  google::protobuf::io::IstreamInputStream istream(&if_stream);
  oak::attestation::v1::ReferenceValues appraisal_policy;
  if (!google::protobuf::TextFormat::Parse(&istream, &appraisal_policy)) {
    LOG(ERROR) << "Failed to parse " << appraisal_policy_file;
    return 1;
  }

  absl::StatusOr<int> port = GetPort();
  if (!port.ok()) {
    LOG(ERROR) << "Cannot get server port " << port.status();
  }

  LOG(INFO) << "Starting TVS server on port " << port;
  privacy_sandbox::tvs::CreateAndStartTvsServer(
      privacy_sandbox::tvs::TvsServerOptions{
          .port = *std::move(port),
          .tvs_private_key = absl::GetFlag(FLAGS_tvs_private_key),
          .appraisal_policy = std::move(appraisal_policy),
      });
  return 0;
}
