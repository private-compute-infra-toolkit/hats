# Dockerfiles for build other components

1. qemu

Most of the dockerfile is borrowed from [QEMU's Github repo]
(https://github.com/qemu/qemu/blob/786fd793b81410fb2a28914315e2f05d2ff6733b/tests/docker/dockerfiles/debian.docker).

A few more lines added for building guest kernel. The guest kernel is at version
6.7.0 while Oak's previous kernel was 6.7.6.

```
cd qemu
docker build -t qemu-builder .
```

To build QEMU from AMD's fork (with Yu's changes):

```
git clone https://github.com/dingelish/AMDSEV.git
docker run -ti --rm -v AMDSEV /amdsev qemu-builder bash
./build.sh --package qemu
```

To build the 6.7.0 guest kernel

```
./build.sh kernel guest
```

The kernel config we're using is a slightly changed version of Oak's kernel
[config](https://github.com/project-oak/oak/blob/f136c000431fb83843b39b2f5befbd0178b2dbfb/oak_containers_kernel/configs/6.7.6/minimal.config).

Eventually we want to use Oak's Nix environment to build QEMU so this dockerfile
will be removed later.

To build the 6.7.6 Oak guest kernel

```
git clone https://github.com/project-oak/oak
cd oak
git checkout f136c000431fb83843b39b2f5befbd0178b2dbfb
cd oak_containers_kernel
make
```
