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

#include <cstdint>
#include <iostream>
#include <optional>
#include <string>
#include <thread>

#ifndef HATS_CLIENT_LAUNCHER_QEMU_H_
#define HATS_CLIENT_LAUNCHER_QEMU_H_

namespace privacy_sandbox::launcher {

// Main Qemu struct
class Qemu final {
 public:
  // Types of confidential VMs
  // TODO(alexorozco): implement TDX once supported
  enum VmType {
    kDefault,
    kSev,
    kSevEs,
    kSevSnp,
  };

  // Represents parameters used for launching VM instances.
  struct Options {
    // Path to the VMM binary to execute.
    std::string vmm_binary;

    // Path to the stage0 image to use.
    std::string stage0_binary;

    // Path to the Linux kernel file to use.
    std::string kernel;

    // Path to the initrd image to use.
    std::string initrd;

    // How much memory to give to the enclave binary, e.g., 256M (M stands for
    // Megabyte, G for Gigabyte).
    std::string memory_size;

    // How many CPUs to give to the VM.
    size_t num_cpus;

    // Size (in kilobytes) of the ramdrive used for the system root.
    size_t ramdrive_size;

    // Optional virtio guest CID for virtio-vsock. If not assigned, defaults to
    // the current thread ID.
    // Warning; This CID needs to be globally unique on the whole host!
    std::optional<size_t> virtio_guest_cid;

    // Pass the specified host PCI device through to the virtual machine using
    // VFIO.
    std::string pci_passthrough;

    // Type of the confidential VM. It could be Default, Sev, SevEs,
    // SevSnp
    VmType vm_type;

    // These 3 values are set by the launcher in the lib.rs file
    // (http://shortn/_ngfzsMDl64)
    uint16_t launcher_service_port;
    uint16_t host_proxy_port;
    uint16_t host_orchestrator_proxy_port;

    // Implements Options for root
    static Options Default();
  };

  Qemu() = delete;
  Qemu(const Qemu&) = delete;
  Qemu& operator=(const Qemu&) = delete;

  void Start();

  std::string GetCommand() const;

  Qemu(const Options& options);

 private:
  std::string command_str_;
};

}  // namespace privacy_sandbox::launcher

#endif  // HATS_CLIENT_LAUNCHER_QEMU_H_
