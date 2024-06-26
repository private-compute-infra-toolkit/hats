#ifndef HATS_CLIENT_LAUNCHER_FORWARDING_TVS_SERVER_FFI_
#define HATS_CLIENT_LAUNCHER_FORWARDING_TVS_SERVER_FFI_

#include "rust/cxx.h"

namespace privacy_sandbox::tvs {

void CreateAndStartForwardingTvsServer(uint32_t port, bool use_tls,
                                       rust::Str target,
                                       rust::Str access_token);

}  // namespace privacy_sandbox::tvs

#endif  // HATS_CLIENT_LAUNCHER_FORWARDING_TVS_SERVER_FFI_
