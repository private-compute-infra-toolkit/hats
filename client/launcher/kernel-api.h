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

#ifndef CLIENT_LAUNCHER_KERNEL_API_H_
#define CLIENT_LAUNCHER_KERNEL_API_H_

#include <unistd.h>

#include <string>

#include "absl/strings/string_view.h"
#include "external/psp-sev/file/psp-sev.h"

namespace privacy_sandbox::client {
// Thin wrapper of the underlying kernel or gcc function call to enable gmock
// for testing purpose. It is not intended to be generalized.
class KernelApiInterface {
 public:
  // open /dev/sev controller
  virtual int OpenSev() const = 0;
  virtual int Close(int fd) const = 0;
  virtual int Ioctl(int fd, sev_issue_cmd& cmd) const = 0;
  virtual void Cpuid(uint32_t command, uint32_t* eax, uint32_t* ebx,
                     uint32_t* ecx, uint32_t* edx) const = 0;
};

class KernelApi : public KernelApiInterface {
 public:
  int OpenSev() const override;
  int Close(int fd) const override;
  int Ioctl(int fd, sev_issue_cmd& cmd) const override;
  void Cpuid(uint32_t command, uint32_t* eax, uint32_t* ebx, uint32_t* ecx,
             uint32_t* edx) const override;
};
}  // namespace privacy_sandbox::client
#endif  // CLIENT_LAUNCHER_KERNEL_API_H_
