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

#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <csignal>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/log/log.h"
#include "absl/random/random.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"

ABSL_FLAG(bool, qemu_use_microvm, false,
          "Whether or not to use microvm for SEV-SNP CVMs.");
// porting from oak qemu launcher: http://shortn/_LgMZgnCwOM
// currently Start() is non-blocking, do not terminate process

namespace privacy_sandbox::client {

// SLIRP assings 10.0.2.15 to the guest.
constexpr char kVmLocalAddress[] = "10.0.2.15";
// Hardcoded launcher address for CVM.
constexpr char kVmLauncherAddress[] = "10.0.2.100";
constexpr uint16_t kVmHatsLauncherPort = 8080;
constexpr char kLocalHost[] = "127.0.0.1";
constexpr uint16_t kVmLocalPort = 8080;
// Host always has address of *2*.
constexpr uint32_t kVmAddrCidHost = 2;

Vmm::Options Vmm::Options::Default() {
  return {
      .vmm_binary = "./qemu-system-x86_64",
      .stage0_binary = "stage0_bin",
      .kernel = "bzImage",
      .initrd = "./target/stage1.cpio",
      .memory_size = "8G",
      .num_cpus = 2,
      .ramdrive_size = 3000000,
      .virtio_guest_cid = std::nullopt,
      .vm_type = VmType::kDefault,
  };
}

absl::StatusOr<std::unique_ptr<Qemu>> Qemu::Create(const Options& options) {
  absl::BitGen bitgen;
  std::string binary = options.vmm_binary;
  std::vector<std::string> args;
  args.push_back(binary);
  args.push_back("-enable-kvm");
  // Use the same CPU as the host otherwise the VMM might complains that CPUID
  // info does not match the expected values.
  args.push_back("-cpu");
  args.push_back("host");

  // Needed to expose advanced CPU features. Specifically RDRAND which is
  // required for remote attestation.
  args.push_back("-m");
  args.push_back(options.memory_size);
  args.push_back("-smp");
  args.push_back(absl::StrCat(options.num_cpus));

  // Disable a bunch of hardware we don't need.
  args.push_back("-nodefaults");
  args.push_back("-nographic");

  // If the VM restarts, don't restart it (we're not expecting any restarts so
  // any restart should be treated as a failure)
  args.push_back("-no-reboot");

  // Use the `microvm` machine as the basis, and ensure ACPI and PCIe are
  // enabled.
  constexpr char kMicroVmCommon[] = "microvm,acpi=on,pcie=on";
  // SEV, SEV-ES, SEV-SNP VMs need confidential guest support and private
  // memory.
  // NOTE: Confidential Guest Support breaks vsock in
  // QEMU v9.0.0-2221-g959269e910-dirty.
  constexpr char kSevMachineSuffix[] =
      ",memory-backend=ram1,confidential-guest-support=sev0";
  // Definition of the private memory.
  std::string sev_common_object =
      absl::StrCat("memory-backend-memfd,id=ram1,size=", options.memory_size,
                   ",share=true,reserve=false");
  // SEV's feature configuration.
  constexpr const char kSevConfigObject[] =
      "id=sev0,cbitpos=51,reduced-phys-bits=1";
  // Generate the parameters and add them command line args
  switch (options.vm_type) {
    case VmType::kDefault:
      args.push_back("-machine");
      args.push_back(kMicroVmCommon);
      break;
    case VmType::kSevSnp:
      args.push_back("-machine");
      if (absl::GetFlag(FLAGS_qemu_use_microvm)) {
        args.push_back(absl::StrCat(kMicroVmCommon, kSevMachineSuffix));
      } else {
        args.push_back(absl::StrCat("q35,acpi=on", kSevMachineSuffix));
      }
      args.push_back("-object");
      args.push_back(sev_common_object);
      args.push_back("-object");
      args.push_back(
          absl::StrCat("sev-snp-guest,", kSevConfigObject, ",id-auth=1"));
      break;
  }

  if (options.network_mode == kRoutableIp) {
    if (options.virtual_bridge.empty()) {
      return absl::FailedPreconditionError(
          "virtual_bridge must be provided for a VM with routable IP.");
    }
    // use TAP.
    char script_template[] = "/tmp/qemu-if-XXXXXX";
    int file_descriptor = mkstemp(script_template);
    if (file_descriptor == -1) {
      return absl::FailedPreconditionError(
          absl::StrCat("mkstemp() failed: ", strerror(errno)));
    }
    std::ofstream script_file;
    script_file.open(script_template);
    script_file << "#!/bin/sh" << std::endl;
    script_file << "/usr/sbin/ip link set dev $1 promisc on" << std::endl;
    script_file << "/usr/sbin/ip address replace 0.0.0.0 dev $1" << std::endl;
    script_file << "/usr/sbin/ip link set dev $1 master "
                << options.virtual_bridge << std::endl;
    script_file << "/usr/sbin/ip link set dev $1 up" << std::endl;
    script_file.close();
    if (close(file_descriptor) == -1) {
      return absl::FailedPreconditionError(
          absl::StrCat("close() failed: ", strerror(errno)));
    }
    if (chmod(script_template, S_IXUSR | S_IRUSR) == -1) {
      return absl::FailedPreconditionError(
          absl::StrCat("chmod() failed: ", strerror(errno)));
    }

    args.push_back("-netdev");
    std::string interface = absl::StrCat(
        "tap", absl::Uniform(bitgen, 0, std::numeric_limits<int>::max()));

    args.push_back(absl::StrCat("tap,id=", interface, ",ifname=", interface,
                                ",script=", script_template));
    args.push_back("-device");
    std::string mac_address = absl::StrFormat(
        "d6:ef:77:16:a5:%02x",
        absl::Uniform(bitgen, 0, std::numeric_limits<uint8_t>::max()));
    args.push_back(absl::StrCat(
        "virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev="
        "netdev,romfile=,netdev=",
        std::move(interface), ",mac=", std::move(mac_address)));
  } else {
    // Set up the networking. `rombar=0` is so that QEMU wouldn't bother with
    // the `efi-virtio.rom` file, as we're not using EFI anyway.
    std::string port_forwarding_rules = "user,id=netdev";
    absl::StrAppend(&port_forwarding_rules, ",hostfwd=tcp:", kLocalHost, ":",
                    options.host_proxy_port, "-", kVmLocalAddress, ":",
                    kVmLocalPort);
    // Allow guest workload to talk to oak launcher service.
    if (options.workload_service_port.has_value()) {
      absl::StrAppend(&port_forwarding_rules,
                      ",guestfwd=tcp:", kVmLauncherAddress, ":",
                      kVmHatsLauncherPort, "-cmd:nc ", kLocalHost, " ",
                      *options.workload_service_port);
    }

    args.push_back("-netdev");
    args.push_back(port_forwarding_rules);
    args.push_back("-device");
    args.push_back(
        "virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev="
        "netdev,romfile=");
  }
  // The CID needs to be globally unique, so we default to the current thread
  // ID (which should be unique on the system). This may have interesting
  // interactions with async code though: if you start two VMMs in the same
  // thread, it won't work. But we don't really have any other good sources of
  // globally unique identifiers available for us, and starting multiple VMMs
  // in one thread should be uncommon.
  // CID < 1024 are privilege ports and binding such port causes invalid
  // argument error.
  size_t random_number = absl::Uniform(bitgen, 1024, 1000000);
  args.push_back("-device");
  args.push_back(absl::StrCat("vhost-vsock-pci,guest-cid=",
                              options.virtio_guest_cid.has_value()
                                  ? *options.virtio_guest_cid
                                  : random_number,
                              ",rombar=0"));

  // And yes, use stage0 as the BIOS.
  args.push_back("-bios");
  args.push_back(options.stage0_binary);
  // stage0 accoutrements: the kernel, initrd and inital kernel cmdline.
  args.push_back("-kernel");
  args.push_back(options.kernel);
  args.push_back("-initrd");
  args.push_back(options.initrd);

  args.push_back("-append");
  std::string cmdline;
  if (options.telnet_port.has_value()) {
    cmdline = "debug ";
  }
  absl::StrAppend(&cmdline, " console=ttyS0 panic=-1 brd.rd_nr=1 ");
  absl::StrAppend(&cmdline, "brd.rd_size=", options.ramdrive_size,
                  " brd.max_part=1 ");
  switch (options.network_mode) {
    case NetworkMode::kRestricted:
      absl::StrAppend(&cmdline, "ip=", kVmLocalAddress,
                      ":::255.255.255.0::enp0s1:off");
      break;
    case kOutboundAllowed:
      absl::StrAppend(&cmdline, "ip=", kVmLocalAddress,
                      "::10.0.2.2:255.255.255.0::enp0s1:off");
      break;
    case kRoutableIp:
      if (options.vm_ip_address.empty()) {
        return absl::FailedPreconditionError(
            "An IP address must be provided for a VM with routable IP.");
      }
      if (options.vm_gateway_address.empty()) {
        return absl::FailedPreconditionError(
            "A gateway address must be provided for a VM with routable IP.");
      }
      absl::StrAppend(&cmdline, "ip=", options.vm_ip_address,
                      "::", options.vm_gateway_address,
                      ":255.255.255.0::enp0s1:off");
      break;
  }
  absl::StrAppend(&cmdline, " quiet -- ", "--launcher-addr=vsock://",
                  kVmAddrCidHost, ":", options.launcher_vsock_port);

  args.push_back(cmdline);

  args.push_back("-serial");
  if (options.telnet_port.has_value()) {
    args.push_back(
        absl::StrCat("telnet:localhost:", *options.telnet_port, ",server"));
  } else {
    args.push_back("stdio");
  }

  return absl::WrapUnique(
      new Qemu(std::move(binary), std::move(args), options.log_to_std));
}

Qemu::Qemu(std::string binary, std::vector<std::string> args, bool log_to_std)
    : binary_(std::move(binary)),
      args_(std::move(args)),
      log_to_std_(log_to_std) {}

namespace {

void ClosePosixObjects(posix_spawn_file_actions_t& file_actions,
                       posix_spawnattr_t attr) {
  posix_spawn_file_actions_destroy(&file_actions);
  posix_spawnattr_destroy(&attr);
}

}  // namespace

// This is a non-blocking op, you must make sure not to terminate your process
absl::Status Qemu::Start() {
  absl::MutexLock lock(&mu_);
  if (started_) {
    return absl::FailedPreconditionError("Qemu was already started");
  }

  started_ = true;
  int file_descriptor = -1;
  if (!log_to_std_) {
    char log_file_template[] = "/tmp/hatsXXXXXX";
    file_descriptor = mkstemp(log_file_template);
    if (file_descriptor == -1) {
      return absl::FailedPreconditionError(
          absl::StrCat("mkstemp() failed: ", strerror(errno)));
    }
    log_filename_ = log_file_template;
    LOG(INFO) << "Creating Temporary Log file: '" << log_filename_ << "'";
  }

  posix_spawn_file_actions_t file_actions;
  if (int r = posix_spawn_file_actions_init(&file_actions); r != 0) {
    return absl::FailedPreconditionError(
        "posix_spawn_file_actions_init() failed.");
  }
  posix_spawnattr_t attr;
  if (int r = posix_spawnattr_init(&attr); r != 0) {
    posix_spawn_file_actions_destroy(&file_actions);
    return absl::FailedPreconditionError("posix_spawnattr_init() failed.");
  }

  if (!log_to_std_) {
    // Redirect stdout and stderr to `log_filename_`.
    if (int r = posix_spawn_file_actions_adddup2(&file_actions, file_descriptor,
                                                 STDOUT_FILENO);
        r != 0) {
      ClosePosixObjects(file_actions, attr);
      return absl::FailedPreconditionError(absl::StrCat(
          "posix_spawn_file_actions_adddup2() failed: ", strerror(r)));
    }
    if (int r = posix_spawn_file_actions_adddup2(&file_actions, file_descriptor,
                                                 STDERR_FILENO);
        r != 0) {
      ClosePosixObjects(file_actions, attr);
      return absl::FailedPreconditionError(absl::StrCat(
          "posix_spawn_file_actions_adddup2() failed: ", strerror(r)));
    }
    if (int r = posix_spawn_file_actions_adddup2(&file_actions, file_descriptor,
                                                 STDIN_FILENO);
        r != 0) {
      ClosePosixObjects(file_actions, attr);
      return absl::FailedPreconditionError(absl::StrCat(
          "posix_spawn_file_actions_adddup2() failed: ", strerror(r)));
    }
  }

  auto argv = std::unique_ptr<const char*[]>(new const char*[args_.size() + 1]);
  // posix_spawn , similar to execvp, expects all arguments binary name in an
  // array of c-strings. The array is terminated with nullptr.
  argv[args_.size()] = nullptr;
  for (size_t i = 0; i < args_.size(); ++i) {
    argv[i] = (char*)args_[i].c_str();
  }
  if (int status =
          posix_spawn(&process_id_, binary_.c_str(), &file_actions, &attr,
                      /*argv=*/const_cast<char**>(argv.get()),
                      /*envp=*/nullptr);
      status != 0) {
    return absl::FailedPreconditionError("Failed to launch qemu");
  }

  ClosePosixObjects(file_actions, attr);
  return absl::OkStatus();
}

std::string Qemu::GetCommand() const {
  return absl::StrCat(binary_, " ", absl::StrJoin(args_, " "));
}

absl::StatusOr<std::string> Qemu::LogFilename() const {
  absl::MutexLock lock(&mu_);
  if (!started_) {
    return absl::FailedPreconditionError("Qemu has not started yet.");
  }
  if (log_to_std_) {
    return absl::FailedPreconditionError(
        "Qemu is setup to log to stdout/stderr.");
  }
  return log_filename_;
}

bool Qemu::CheckStatus() const {
  // kill(pid, 0) sends an empty signal to check on the staus of pid
  // kill only returns nonzero (program terminated) when the parent process
  // waits on it first, o/w kill(pid, 0) always returns 0
  waitpid(process_id_, /*wstatus=*/nullptr, WNOHANG);
  return kill(process_id_, 0) == 0;
}

void Qemu::Wait() {
  absl::MutexLock lock(&mu_);
  waitpid(process_id_, /*wstatus=*/nullptr, 0);
}

void Qemu::Shutdown() {
  absl::MutexLock lock(&mu_);
  // Graceful shutdown signal.
  kill(process_id_, SIGTERM);
}

}  // namespace privacy_sandbox::client
