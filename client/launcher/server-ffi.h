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
  // Private key to authenticate with TVS.
  rust::Str tvs_authentication_key;

  // Parc server options.
  bool enable_parc;
  rust::Str parc_parameters_file;
  rust::Str parc_blobstore_root;
};

void CreateAndStartServers(const LauncherServerOptions& options);

}  // namespace privacy_sandbox::launcher

#endif  // HATS_CLIENT_LAUNCHER_SERVER_FFI_
