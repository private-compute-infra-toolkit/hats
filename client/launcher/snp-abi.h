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

// Defines parsing binary data into CPP structs.
#ifndef CLIENT_LAUNCHER_SNP_ABI_H_
#define CLIENT_LAUNCHER_SNP_ABI_H_

#include <unistd.h>
// Structs come from Archived tool:
// https://github.com/AMDESE/sev-tool/blob/master/src/sevapi.h
// The structs may not be available in linux kernel.
namespace privacy_sandbox::client {
// TCB bytes pointed by snp_platform_status_buffer.reported_tcb.
typedef union snp_tcb_version  // TCB
{
  struct {
    uint8_t boot_loader;  // SVN of PSP bootloader
    uint8_t tee;          // SVN of PSP operating system
    uint8_t reserved[4];
    uint8_t snp;        // SVN of SNP firmware
    uint8_t microcode;  // Lowest current patch level of all the cores
  } __attribute__((packed)) f;
  uint64_t val;
} __attribute__((packed)) snp_tcb_version_t;
static_assert(sizeof(snp_tcb_version_t) == sizeof(uint64_t),
              "Error, static assertion failed");

typedef struct __attribute__((__packed__)) snp_platform_status_buffer_t {
  uint8_t api_major;
  uint8_t api_minor;
  uint8_t state;
  uint8_t is_rmp_init : 1; /* bit 0 */
  uint8_t reserved : 7;    /* bits 1 to 7 */
  uint32_t build_id;
  uint8_t mask_chip_id : 1; /* bit 0 */
  uint32_t reserved2 : 31;  /* bits 1 to 31 */
  uint32_t guest_count;     /* SNP Guest count */
  uint64_t tcb_version;     /* Platform/installed version */
  uint64_t reported_tcb;    /* SetReportedTCB() version */
} snp_platform_status_buffer;
}  // namespace privacy_sandbox::client

#endif  // CLIENT_LAUNCHER_SNP_ABI_H_
