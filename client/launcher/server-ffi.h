#ifndef HATS_CLIENT_LAUNCHER_SERVER_FFI_
#define HATS_CLIENT_LAUNCHER_SERVER_FFI_

#include "rust/cxx.h"

namespace privacy_sandbox::launcher {

struct LauncherServerOptions {
  uint32_t port;
  // Forwarding TVS server options.
  bool forwarding_use_tls;
  rust::Str forwarding_target;
  rust::Str forwarding_access_token;

  // Parc server options.
  bool enable_parc;
  rust::Str parc_parameters_file;
  rust::Str parc_blobstore_root;
};

void CreateAndStartServers(const LauncherServerOptions& options);

}  // namespace privacy_sandbox::launcher

#endif  // HATS_CLIENT_LAUNCHER_SERVER_FFI_
