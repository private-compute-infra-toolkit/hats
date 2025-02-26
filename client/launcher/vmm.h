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

#include <memory>
#include <optional>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"

#ifndef HATS_CLIENT_LAUNCHER_VMM_H_
#define HATS_CLIENT_LAUNCHER_VMM_H_

namespace privacy_sandbox::client {

// Defines an interface for implementing a VMM.
// This interface defines common options availble to the VMMs
// as well as common functionality such as turning up a VM and
// or shutting it down
class Vmm {
 public:
  // Types of confidential VMs
  enum VmType {
    kDefault,
    kSevSnp,
  };

  enum NetworkMode {
    kRestricted,
    kOutboundAllowed,
    // Assign a routable IP address to the CVM.
    // We use taps here so the CVM is accessible from the host (and outside if
    // the hosts enables IP forwarding).
    kRoutableIp,
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

    // Type of the confidential VM. It could be Default, Sev, SevEs,
    // SevSnp
    VmType vm_type;

    // Vsock port that the launcher gRpc server is listening for.
    uint32_t launcher_vsock_port;

    // TCP port for the workload services.
    std::optional<uint16_t> workload_service_port;

    // Port to proxy traffic to the enclave listening to TCP 8080.
    uint16_t host_proxy_port;

    // Implements Options for root
    static Options Default();

    // Specifies networking policies.
    NetworkMode network_mode;
    // If specified, the VM will start in debug mode and listens to a the port
    // specified.
    std::optional<uint16_t> telnet_port = std::nullopt;

    // The following parameters are only applicable if network_mode is
    // kRoutableIp.

    // Virtual bridge to add the TAP interface to.
    std::string virtual_bridge;
    // An IP address to be assigned to the CVM.
    std::string vm_ip_address;
    // A gateway for the CVM to forward outbound packets to.
    std::string vm_gateway_address;
    // Output log to stdout/stderr
    bool log_to_std = false;
  };

  virtual ~Vmm() = default;
  static absl::StatusOr<std::unique_ptr<Vmm>> Create(const Options& options);

  // This function should be called once and only once.
  // The function returns an error if it was called multiple times.
  virtual absl::Status Start() = 0;

  // Exposed for unit test.
  virtual std::string GetCommand() const = 0;

  // Return the file where VMM stderr and stdout are written.
  virtual absl::StatusOr<std::string> LogFilename() const = 0;

  // Check status of the Vmm process
  virtual bool CheckStatus() const = 0;

  // Wait until Vmm terminates.
  virtual void Wait() = 0;

  // Shutdown Vmm subprocess.
  virtual void Shutdown() = 0;
};

}  // namespace privacy_sandbox::client

#endif  // HATS_CLIENT_LAUNCHER_VMM_H_
