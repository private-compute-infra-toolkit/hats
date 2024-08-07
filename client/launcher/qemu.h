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
#include <cstdio>
#include <iostream>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "absl/status/status.h"

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

  enum NetworkMode {
    kRestricted,
    kOutboundAllowed,
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
    std::string memory_size = "8G";

    // How many CPUs to give to the VM.
    size_t num_cpus = 1;

    // Size (in kilobytes) of the ramdrive used for the system root.
    size_t ramdrive_size = 10000000;

    // Optional virtio guest CID for virtio-vsock. If not assigned, defaults to
    // the current thread ID.
    // Warning; This CID needs to be globally unique on the whole host!
    std::optional<size_t> virtio_guest_cid = std::nullopt;

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

    // Specifies networking policies.
    NetworkMode network_mode;
    // If specified, the VM will start in debug mode and listens to a the port
    // specified.
    std::optional<uint16_t> telnet_port = std::nullopt;
  };

  Qemu() = delete;
  Qemu(const Qemu&) = delete;
  Qemu& operator=(const Qemu&) = delete;
  Qemu(const Options& options);

  // This function should be called once and only once.
  // The function returns an error if it was called multiple times.
  absl::Status Start() ABSL_LOCKS_EXCLUDED(mu_);

  // Exposed for unit test.
  std::string GetCommand() const;

  // Return the file where VMM stderr and stdout are written.
  std::string LogFilename() ABSL_LOCKS_EXCLUDED(mu_) const;

  // Wait until QEMU terminates.
  void Wait() ABSL_LOCKS_EXCLUDED(mu_);

 private:
  const std::string binary_;
  std::vector<std::string> args_;
  mutable absl::Mutex mu_;
  // Whether a QEMU was started or not.
  bool started_ ABSL_GUARDED_BY(mu_) = false;
  // File where VMM stdout and stderr are directed to.
  FILE* log_file_ ABSL_GUARDED_BY(mu_) = nullptr;
  // Process id of the QEMU process.
  pid_t process_id_ ABSL_GUARDED_BY(mu_);
  // file name where qemu output is written to.
  std::string log_filename_ ABSL_GUARDED_BY(mu_);
};

}  // namespace privacy_sandbox::launcher

#endif  // HATS_CLIENT_LAUNCHER_QEMU_H_
