#include <fstream>
#include <string>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "external/oak/proto/attestation/reference_value.pb.h"
#include "google/protobuf/io/zero_copy_stream_impl.h"
#include "google/protobuf/text_format.h"
#include "tvs/proto/tvs_messages.pb.h"
#include "tvs/trusted_tvs/src/lib.rs.h"
#include "tvs/untrusted_tvs/tvs-server.h"

ABSL_FLAG(int, port, 8081, "Port TVS server listens to.");
// TODO(alwabel): implement a better key provisioning.
ABSL_FLAG(std::string, tvs_private_key, "",
          "Private key for NK-Noise handshake protocol.");
ABSL_FLAG(std::string, appraisal_policy_file, "",
          "Policy that defines acceptable evidence.");

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

  LOG(INFO) << "Starting TVS server on port " << absl::GetFlag(FLAGS_port);
  privacy_sandbox::tvs::CreateAndStartTvsServer(
      privacy_sandbox::tvs::TvsServerOptions{
          .port = absl::GetFlag(FLAGS_port),
          .tvs_private_key = absl::GetFlag(FLAGS_tvs_private_key),
          .appraisal_policy = std::move(appraisal_policy),
      });
  return 0;
}
