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

#include "client/launcher/qemu.h"

#include <chrono>
#include <cstdint>
#include <iostream>
#include <numeric>
#include <random>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"

// porting from oak qemu launcher: http://shortn/_LgMZgnCwOM
// currently Start() is non-blocking, do not terminate process

namespace privacy_sandbox::launcher {

// values from http://shortn/_ehIJXlZa2X
constexpr char kVmLocalAddress[] = "10.0.2.15";
constexpr char kLocalHost[] = "127.0.0.1";
constexpr uint16_t kVmOrchestratorLocalPort = 4000;
constexpr uint16_t kVmLocalPort = 8080;
// value from tokio_vsock documentation http://shortn/_xWSQlEKHnR
constexpr uint32_t kVmAddrCidHost = 2;

Qemu::Options Qemu::Options::Default() {
  constexpr char kVmm_binary[] = "./qemu-system-x86_64";
  constexpr char kStage0_binary[] = "stage0_bin";
  constexpr char kKernel[] = "vanilla_bzImage";
  constexpr char kInitrd[] = "./target/stage1.cpio";
  return {
      kVmm_binary,
      kStage0_binary,
      kKernel,
      kInitrd,
      "8G",          // memory_size
      2,             // num_cpus
      3000000,       // ramdrive_size:
      std::nullopt,  // virtio_guest_cid
      "",            // pci_passthrough
      VmType::kDefault,
  };
}

Qemu::Qemu(const Qemu::Options& options) {
  // (TODO):open socket for console debugging
  // command_str will be where we setup all options to run qemu
  std::string command_str =
      absl::StrCat(options.vmm_binary, " -enable-kvm -cpu host ");

  // Needed to expose advanced CPU features. Specifically RDRAND which is
  // required for remote attestation.
  absl::StrAppend(&command_str, "-m ", options.memory_size, " ");

  absl::StrAppend(&command_str, "-smp ", options.num_cpus, " ");
  // Disable a bunch of hardware we don't need.
  absl::StrAppend(&command_str, "-nodefaults -nographic ");
  // If the VM restarts, don't restart it (we're not expecting any restarts so
  // any restart should be treated as a failure)
  absl::StrAppend(&command_str, "-no-reboot ");
  // Use the `microvm` machine as the basis, and ensure ACPI and PCIe are
  // enabled.
  constexpr char kMicrovm_common[] = "microvm,acpi=on,pcie=on";
  // SEV, SEV-ES, SEV-SNP VMs need confidential guest support and private
  // memory.
  constexpr char kSev_machine_suffix[] =
      ",confidential-guest-support=sev0,memory-backend=ram1";
  // Definition of the private memory.
  std::string sev_common_object =
      absl::StrCat("memory-backend-memfd,id=ram1,size=", options.memory_size,
                   ",share=true,reserve=false");
  // SEV's feature configuration.
  constexpr char kSev_config_object[] =
      "id=sev0,cbitpos=51,reduced-phys-bits=1";
  // Generate the parameters and add them command line args
  switch (options.vm_type) {
    case VmType::kDefault:
      absl::StrAppend(&command_str, "-machine ", kMicrovm_common, " ");
      break;
    case VmType::kSev:
      absl::StrAppend(&command_str, "-machine ", kMicrovm_common, " ");
      absl::StrAppend(&command_str, "-object ", sev_common_object, " ");
      absl::StrAppend(&command_str, "-object ", "sev-guest,", sev_common_object,
                      ",policy=0x1 ");
      break;
    case VmType::kSevEs:
      absl::StrAppend(&command_str, "-machine ", kMicrovm_common,
                      kSev_machine_suffix, " ");
      absl::StrAppend(&command_str, "-object ", sev_common_object, " ");
      absl::StrAppend(&command_str, "-object ", "sev-guest,", sev_common_object,
                      ",policy=0x5 ");
      break;
    case VmType::kSevSnp:
      absl::StrAppend(&command_str, "-machine ", kMicrovm_common,
                      kSev_machine_suffix, " ");
      absl::StrAppend(&command_str, "-object ", sev_common_object, " ");
      absl::StrAppend(&command_str, "-object ", "sev-snp-guest,",
                      kSev_config_object, ",id-auth= ");
      break;
  }
  // (TODO) alexorozco: Implement qemu telnet console debugging

  // Set up the networking. `rombar=0` is so that QEMU wouldn't bother with the
  // `efi-virtio.rom` file, as we're not using EFI anyway.
  // (TODO) alexorozco: implement forwarding to guest
  std::string host_fwd =
      absl::StrFormat("hostfwd=tcp:%s:%u-%s:%u", kLocalHost,
                      options.host_orchestrator_proxy_port, kVmLocalAddress,
                      kVmOrchestratorLocalPort);
  absl::StrAppend(&command_str, "-netdev user,id=netdev,");
  absl::StrAppend(
      &command_str, std::move(host_fwd),
      absl::StrFormat(",hostfwd=tcp:%s:%u-%s:%u", kLocalHost,
                      options.host_proxy_port, kVmLocalAddress, kVmLocalPort),
      " ");
  absl::StrAppend(&command_str,
                  "-device "
                  "virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev="
                  "netdev,romfile= ");
  // The CID needs to be globally unique, so we default to the current thread ID
  // (which should be unique on the system). This may have interesting
  // interactions with async code though: if you start two VMMs in the same
  // thread, it won't work. But we don't really have any other good sources of
  // globally unique identifiers available for us, and starting multiple VMMs in
  // one thread should be uncommon.
  if (options.virtio_guest_cid.has_value()) {
    absl::StrAppend(
        &command_str,
        absl::StrFormat("-device vhost-vsock-pci,guest-cid=%u,rombar=0",
                        *options.virtio_guest_cid),
        " ");
  } else {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, 1000000000);
    size_t random_number = distrib(gen);
    absl::StrAppend(&command_str,
                    "-device vhost-vsock-pci,guest-cid=", random_number,
                    ",rombar=0 ");
  }
  // And yes, use stage0 as the BIOS.
  absl::StrAppend(&command_str, "-bios ", options.stage0_binary, " ");
  // stage0 accoutrements: the kernel, initrd and inital kernel cmdline.
  absl::StrAppend(&command_str, "-kernel ", options.kernel, " ");
  absl::StrAppend(&command_str, "-initrd ", options.initrd, " ");

  absl::StrAppend(&command_str, "-append ");
  // TODO(alexorozco): add debugging flag here
  absl::StrAppend(&command_str, "console=\"ttyS0 ");
  absl::StrAppend(&command_str, "panic=-1 ");
  absl::StrAppend(&command_str, "brd.rd_nr=1 ");
  absl::StrAppend(&command_str,
                  absl::StrFormat("brd.rd_size=%u", options.ramdrive_size),
                  " ");
  absl::StrAppend(&command_str, "brd.max_part=1 ");
  absl::StrAppend(
      &command_str,
      absl::StrFormat("ip=%s:::255.255.255.0::eth0:off", kVmLocalAddress), " ");
  absl::StrAppend(&command_str, "quiet ");
  absl::StrAppend(&command_str, "-- ");
  absl::StrAppend(
      &command_str,
      absl::StrFormat("--launcher-addr=vsock://%u:%u\"", kVmAddrCidHost,
                      options.launcher_service_port));

  command_str_ = command_str;
}

std::string Qemu::GetCommand() const { return command_str_; }

// This is a non-blocking op, you must make sure not to terminate your process
void Qemu::Start() { std::system(command_str_.c_str()); }

}  // namespace privacy_sandbox::launcher
