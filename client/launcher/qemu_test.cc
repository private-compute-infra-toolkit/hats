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

#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <thread>

#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "gtest/gtest.h"

namespace privacy_sandbox::client {
namespace {

using ::absl_testing::StatusIs;
using ::testing::HasSubstr;

struct QemuLauncherTestCase {
  std::string test_name;
  Qemu::Options options;
  std::string expected_output;
};

using QemuLauncherTest = testing::TestWithParam<QemuLauncherTestCase>;

INSTANTIATE_TEST_SUITE_P(
    QemuLauncherTests, QemuLauncherTest,
    testing::ValuesIn<QemuLauncherTestCase>({
        {.test_name = "SuccessSevSnp",
         .options =
             {
                 .vmm_binary = "./qemu-system-x86_64",
                 .stage0_binary =
                     "/home/user/hats_kv/hats_kv/prebuilt/stage0_bin",
                 .kernel = "/home/user/hats_kv/hats_kv/prebuilt/"
                           "vanilla_bzImage",
                 .initrd = "/home/user/hats_kv/hats_kv/prebuilt/stage1.cpio",
                 .memory_size = "8G",
                 .num_cpus = 1,
                 .ramdrive_size = 6,
                 .virtio_guest_cid = 8,
                 .pci_passthrough = "pci_passthrough",
                 .vm_type = Qemu::VmType::kSevSnp,
                 .launcher_service_port = 36317,
                 .host_proxy_port = 4000,
                 .host_orchestrator_proxy_port = 1080,
             },
         .expected_output =
             "./qemu-system-x86_64 ./qemu-system-x86_64 -enable-kvm -cpu host "
             "-m 8G -smp 1 -nodefaults -nographic -no-reboot -machine "
             "microvm,acpi=on,pcie=on,memory-backend=ram1,confidential-guest-"
             "support=sev0 -object "
             "memory-backend-memfd,id=ram1,size=8G,share=true,reserve=false "
             "-object "
             "sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,id-auth=1 "
             "-netdev "
             "user,id=netdev,hostfwd=tcp:127.0.0.1:1080-10.0.2.15:4000,"
             "guestfwd=tcp:10."
             "0.2.100:8080-cmd:nc 127.0.0.1 "
             "36317,hostfwd=tcp:127.0.0.1:4000-10.0.2.15:8080 -device "
             "virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev="
             "netdev,romfile= -device vhost-vsock-pci,guest-cid=8,rombar=0 "
             "-bios /home/user/hats_kv/hats_kv/prebuilt/stage0_bin -kernel "
             "/home/user/hats_kv/hats_kv/prebuilt/vanilla_bzImage -initrd "
             "/home/user/hats_kv/hats_kv/prebuilt/stage1.cpio -append  "
             "console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=6 brd.max_part=1 "
             "ip=10.0.2.15:::255.255.255.0::enp0s1:off quiet -- "
             "--launcher-addr=vsock://2:36317"},
        {
            .test_name = "SuccessSevEs",
            .options =
                {
                    .vmm_binary = "vmm_binary",
                    .stage0_binary = "stage0_binary",
                    .kernel = "kernel",
                    .initrd = "initrd",
                    .memory_size = "memory_size",
                    .num_cpus = 5,
                    .ramdrive_size = 6,
                    .virtio_guest_cid = 8,
                    .pci_passthrough = "pci_passthrough",
                    .vm_type = Qemu::VmType::kSevEs,
                    .launcher_service_port = 8080,
                    .host_proxy_port = 4000,
                    .host_orchestrator_proxy_port = 1080,
                },
            .expected_output =
                "vmm_binary vmm_binary -enable-kvm -cpu host -m memory_size "
                "-smp 5 -nodefaults -nographic -no-reboot -machine "
                "microvm,acpi=on,pcie=on -machine "
                "memory-backend-memfd,id=ram1,size=memory_size,share=true,"
                "reserve=false -object "
                "sev-guest,memory-backend-memfd,id=ram1,size=memory_size,share="
                "true,reserve=false,policy=0x1 -netdev "
                "user,id=netdev,"
                "hostfwd=tcp:127.0.0.1:1080-10.0.2.15:4000,guestfwd=tcp:"
                "10.0.2.100:8080-cmd:nc 127.0.0.1 8080,"
                "hostfwd=tcp:127.0.0.1:4000-10.0.2.15:8080 -device "
                "virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev="
                "netdev,romfile= -device vhost-vsock-pci,guest-cid=8,rombar=0 "
                "-bios stage0_binary -kernel kernel -initrd initrd -append  "
                "console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=6 "
                "brd.max_part=1 ip=10.0.2.15:::255.255.255.0::enp0s1:off quiet "
                "-- --launcher-addr=vsock://2:8080",
        },
        {
            .test_name = "SuccessVmTypeDefault",
            .options =
                {
                    .vmm_binary = "vmm_binary",
                    .stage0_binary = "stage0_binary",
                    .kernel = "kernel",
                    .initrd = "initrd",
                    .memory_size = "memory_size",
                    .num_cpus = 5,
                    .ramdrive_size = 6,
                    .virtio_guest_cid = 8,
                    .pci_passthrough = "pci_passthrough",
                    .vm_type = Qemu::VmType::kDefault,
                    .launcher_service_port = 8080,
                    .host_proxy_port = 4000,
                    .host_orchestrator_proxy_port = 1080,
                },
            .expected_output =
                "vmm_binary vmm_binary -enable-kvm -cpu host -m memory_size "
                "-smp 5 -nodefaults -nographic -no-reboot -machine "
                "microvm,acpi=on,pcie=on -netdev "
                "user,id=netdev,"
                "hostfwd=tcp:127.0.0.1:1080-10.0.2.15:4000,guestfwd=tcp:"
                "10.0.2.100:8080-cmd:nc 127.0.0.1 8080,"
                "hostfwd=tcp:127.0.0.1:4000-10.0.2.15:8080 -device "
                "virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev="
                "netdev,romfile= -device vhost-vsock-pci,guest-cid=8,rombar=0 "
                "-bios stage0_binary -kernel kernel -initrd initrd -append  "
                "console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=6 "
                "brd.max_part=1 ip=10.0.2.15:::255.255.255.0::enp0s1:off quiet "
                "-- --launcher-addr=vsock://2:8080",
        },
        {
            .test_name = "TelnetPort",
            .options =
                {
                    .vmm_binary = "vmm_binary",
                    .stage0_binary = "_teststage0_binary",
                    .kernel = "test_kernel",
                    .initrd = "initrd",
                    .memory_size = "100G",
                    .num_cpus = 50,
                    .ramdrive_size = 30,
                    .virtio_guest_cid = 80,
                    .vm_type = Qemu::VmType::kSevSnp,
                    .launcher_service_port = 8080,
                    .host_proxy_port = 4000,
                    .host_orchestrator_proxy_port = 1080,
                },
            .expected_output =
                "vmm_binary vmm_binary -enable-kvm -cpu host -m 100G -smp 50 "
                "-nodefaults -nographic -no-reboot -machine "
                "microvm,acpi=on,pcie=on,memory-backend=ram1,confidential-"
                "guest-support=sev0 -object "
                "memory-backend-memfd,id=ram1,size=100G,share=true,reserve="
                "false -object "
                "sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,id-auth="
                "1 -netdev "
                "user,id=netdev,"
                "hostfwd=tcp:127.0.0.1:1080-10.0.2.15:4000,guestfwd=tcp:"
                "10.0.2.100:8080-cmd:nc 127.0.0.1 8080,"
                "hostfwd=tcp:127.0.0.1:4000-10.0.2.15:8080 -device "
                "virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev="
                "netdev,romfile= -device vhost-vsock-pci,guest-cid=80,rombar=0 "
                "-bios _teststage0_binary -kernel test_kernel -initrd initrd "
                "-append  console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=30 "
                "brd.max_part=1 ip=10.0.2.15:::255.255.255.0::enp0s1:off quiet "
                "-- --launcher-addr=vsock://2:8080",
        },
        {
            .test_name = "OutboundNetwork",
            .options =
                {
                    .vmm_binary = "vmm_binary",
                    .stage0_binary = "_teststage0_binary",
                    .kernel = "test_kernel",
                    .initrd = "initrd",
                    .ramdrive_size = 30,
                    .virtio_guest_cid = 80,
                    .vm_type = Qemu::VmType::kSevSnp,
                    .launcher_service_port = 8080,
                    .host_proxy_port = 4000,
                    .host_orchestrator_proxy_port = 1080,
                    .network_mode = Qemu::NetworkMode::kOutboundAllowed,
                },
            .expected_output =
                "vmm_binary vmm_binary -enable-kvm -cpu host -m 8G -smp 1 "
                "-nodefaults -nographic -no-reboot -machine "
                "microvm,acpi=on,pcie=on,memory-backend=ram1,confidential-"
                "guest-support=sev0 -object "
                "memory-backend-memfd,id=ram1,size=8G,share=true,reserve=false "
                "-object "
                "sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,id-auth="
                "1 -netdev "
                "user,id=netdev,"
                "hostfwd=tcp:127.0.0.1:1080-10.0.2.15:4000,guestfwd=tcp:"
                "10.0.2.100:8080-cmd:nc 127.0.0.1 8080,"
                "hostfwd=tcp:127.0.0.1:4000-10.0.2.15:8080 -device "
                "virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev="
                "netdev,romfile= -device vhost-vsock-pci,guest-cid=80,rombar=0 "
                "-bios _teststage0_binary -kernel test_kernel -initrd initrd "
                "-append  console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=30 "
                "brd.max_part=1 "
                "ip=10.0.2.15::10.0.2.2:255.255.255.0::enp0s1:off quiet -- "
                "--launcher-addr=vsock://2:8080",
        },
    }));

TEST_P(QemuLauncherTest, Success) {
  const QemuLauncherTestCase& test_case = GetParam();
  absl::StatusOr<std::unique_ptr<Qemu>> qemu = Qemu::Create(test_case.options);
  ASSERT_TRUE(qemu.ok());
  EXPECT_EQ((*qemu)->GetCommand(), test_case.expected_output);
}

// Separate test case for default options so we can fix the virtio_guest_cid
// b/c guest_cid is generated randomly when we don't pass in the parameter
TEST(Qemu, SuccessDefaultOptions) {
  Qemu::Options options = Qemu::Options::Default();
  options.virtio_guest_cid = 2;
  absl::StatusOr<std::unique_ptr<Qemu>> qemu = Qemu::Create(options);
  ASSERT_TRUE(qemu.ok());
  EXPECT_EQ(
      (*qemu)->GetCommand(),
      "./qemu-system-x86_64 ./qemu-system-x86_64 -enable-kvm -cpu host -m 8G "
      "-smp 2 -nodefaults -nographic -no-reboot -machine "
      "microvm,acpi=on,pcie=on -netdev "
      "user,id=netdev,"
      "hostfwd=tcp:127.0.0.1:0-10.0.2.15:4000,guestfwd=tcp:10.0.2.100:8080-"
      "cmd:nc 127.0.0.1 0,hostfwd=tcp:127.0.0.1:0-10.0.2.15:8080 -device "
      "virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=netdev,"
      "romfile= -device vhost-vsock-pci,guest-cid=2,rombar=0 -bios stage0_bin "
      "-kernel vanilla_bzImage -initrd ./target/stage1.cpio -append  "
      "console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=3000000 brd.max_part=1 "
      "ip=10.0.2.15:::255.255.255.0::enp0s1:off quiet -- "
      "--launcher-addr=vsock://2:0");
}

TEST(Qemu, kRoutableIp) {
  absl::StatusOr<std::unique_ptr<Qemu>> qemu = Qemu::Create({
      .vmm_binary = "vmm_binary",
      .stage0_binary = "_teststage0_binary",
      .kernel = "test_kernel",
      .initrd = "initrd",
      .virtio_guest_cid = 5,
      .network_mode = Qemu::NetworkMode::kRoutableIp,
      .virtual_bridge = "br0",
      .vm_ip_address = "192.168.110.60",
      .vm_gateway_address = "192.168.110.1",
  });
  ASSERT_TRUE(qemu.ok());
  EXPECT_THAT(
      (*qemu)->GetCommand(),
      AllOf(HasSubstr("vmm_binary vmm_binary -enable-kvm -cpu host -m 8G -smp "
                      "1 -nodefaults -nographic -no-reboot -machine "
                      "microvm,acpi=on,pcie=on -netdev tap,id=tap"),
            HasSubstr(",ifname="), HasSubstr(",script="),
            HasSubstr("-device "
                      "virtio-net-pci,disable-legacy=on,iommu_platform=true,"
                      "netdev=netdev,romfile=,netdev=tap"),
            HasSubstr("-device vhost-vsock-pci,guest-cid=5,rombar=0 -bios "
                      "_teststage0_binary -kernel test_kernel -initrd initrd "
                      "-append  console=ttyS0 panic=-1 brd.rd_nr=1 "
                      "brd.rd_size=10000000 brd.max_part=1 "
                      "ip=192.168.110.60::192.168.110.1:255.255.255.0::enp0s1:"
                      "off quiet -- --launcher-addr=vsock://2:0")));
}

TEST(Qemu, CreationError) {
  EXPECT_THAT(
      Qemu::Create({
          .network_mode = Qemu::NetworkMode::kRoutableIp,
          .vm_ip_address = "192.168.110.60",
          .vm_gateway_address = "192.168.110.1",
      }),
      StatusIs(
          absl::StatusCode::kFailedPrecondition,
          HasSubstr(
              "virtual_bridge must be provided for a VM with routable IP")));

  EXPECT_THAT(Qemu::Create({
                  .network_mode = Qemu::NetworkMode::kRoutableIp,
                  .virtual_bridge = "br0",
                  .vm_gateway_address = "192.168.110.1",
              }),
              StatusIs(absl::StatusCode::kFailedPrecondition,
                       HasSubstr("An IP address must be provided")));

  EXPECT_THAT(Qemu::Create({
                  .network_mode = Qemu::NetworkMode::kRoutableIp,
                  .virtual_bridge = "br0",
                  .vm_ip_address = "192.168.110.60",
              }),
              StatusIs(absl::StatusCode::kFailedPrecondition,
                       HasSubstr("A gateway address must be provided")));
}

}  // namespace
}  // namespace privacy_sandbox::client
