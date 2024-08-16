#include <fstream>
#include <iostream>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "absl/status/statusor.h"
#include "client/launcher/launcher.h"
#include "client/proto/launcher_config.pb.h"
#include "google/protobuf/text_format.h"
ABSL_FLAG(std::string, launcher_config_path, "./launcher_config.textproto",
          "path to read launcher configuration");
int main(int argc, char* argv[]) {
  absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();

  privacy_sandbox::client::LauncherConfig config;
  std::string launcher_config_path = absl::GetFlag(FLAGS_launcher_config_path);
  if (launcher_config_path.empty()) {
    LOG(ERROR)
        << "empty launcher_config_path flag, expect some valid path to file.";
    return 1;
  }

  std::ifstream file(launcher_config_path);
  if (!file.is_open()) {
    LOG(ERROR) << "failed to open file " << launcher_config_path;
    return 1;
  }
  std::string raw_config((std::istreambuf_iterator<char>(file)),
                         (std::istreambuf_iterator<char>()));
  file.close();

  if (!google::protobuf::TextFormat::ParseFromString(raw_config, &config)) {
    LOG(ERROR) << "invalid json string message at path "
               << launcher_config_path;
    return 1;
  }

  auto launcher = privacy_sandbox::client::HatsLauncher::Create(config);
  // TODO(b/358628725): Finish up qemu process spinup.
  return 0;
}
