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

#include "absl/log/check.h"
#include "client/launcher/kernel-api.h"
#include "client/launcher/snp-abi.h"
#include "external/psp-sev/file/psp-sev.h"

namespace pcit::client {
class KernelApiMock : public KernelApiInterface {
 public:
  int OpenSev() const override { return 133; }
  int Close(int fd) const override { return 0; }
  int Ioctl(int fd, sev_issue_cmd& cmd) const override {
    // Fake execute the sev command:
    // Test only code. Really dangerous type casting from uint64_t to a memory
    // location.
    switch (cmd.cmd) {
      case SNP_PLATFORM_STATUS: {
        auto buffer =
            reinterpret_cast<pcit::client::snp_platform_status_buffer*>(
                cmd.data);
        buffer->reported_tcb = reported_tcb_;
      } break;
      case SEV_GET_ID2: {
        auto get_id2 = reinterpret_cast<sev_user_data_get_id2*>(cmd.data);
        CHECK(get_id2 != nullptr);
        auto get_id = reinterpret_cast<sev_user_data_get_id*>(get_id2->address);
        CHECK(get_id != nullptr);
        for (size_t i = 0; i < 64; i++) {
          get_id->socket1[i] = sev_user_get_id_socket1_[i];
        }
      } break;
      default:
        // NOT SUPPORTED;
        CHECK(false);
    }
    cmd.error = sev_cmd_err_code_;
    return 0;
  }

  void Cpuid(uint32_t command, uint32_t* eax, uint32_t* ebx, uint32_t* ecx,
             uint32_t* edx) const override {
    *eax = eax_;
    *ebx = ebx_;
    *ecx = ecx_;
    *edx = edx_;
  }

  uint32_t eax_;
  uint32_t ebx_;
  uint32_t ecx_;
  uint32_t edx_;
  uint32_t sev_cmd_err_code_;
  uint64_t reported_tcb_;
  __u8 sev_user_get_id_socket1_[64];
};
}  // namespace pcit::client
