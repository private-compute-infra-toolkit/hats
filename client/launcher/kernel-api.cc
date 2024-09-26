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

#include "kernel-api.h"

#include <cpuid.h>      // gcc api for compiling into assembly code.
#include <fcntl.h>      // open, O_RDWR
#include <sys/ioctl.h>  // ioctl
#include <unistd.h>     // open / close

#include "external/psp-sev/file/psp-sev.h"

namespace privacy_sandbox::client {
void KernelApi::Cpuid(uint32_t command, uint32_t* eax, uint32_t* ebx,
                      uint32_t* ecx, uint32_t* edx) const {
  uint32_t eax1, ebx1, ecx1, edx1;
  // __cpuid is a macro provided by gcc cpuid.h to compile assembly into it.
  __cpuid(command, eax1, ebx1, ecx1, edx1);
  *eax = eax1;
  *ebx = ebx1;
  *ecx = ecx1;
  *edx = edx1;
}

int KernelApi::OpenSev() const { return open("/dev/sev", O_RDWR); }
int KernelApi::Close(int fd) const { return close(fd); }
int KernelApi::Ioctl(int fd, sev_issue_cmd& cmd) const {
  return ioctl(fd, SEV_ISSUE_CMD, &cmd);
}
}  // namespace privacy_sandbox::client
