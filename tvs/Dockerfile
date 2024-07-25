FROM ubuntu:20.04

RUN apt-get update && apt-get -y install \
  curl \
  gnupg2 \
  build-essential \
  g++-10 \
  gcc-10 \
  git \
  libclang-dev

RUN DEBIAN_FRONTEND=noninteractive TZ=America/Los_Angeles apt-get -y install cmake

RUN update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-10 10 && \
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-10 10

RUN echo "deb [arch=amd64] http://storage.googleapis.com/bazel-apt stable jdk1.8" | tee /etc/apt/sources.list.d/bazel.list

RUN curl https://bazel.build/bazel-release.pub.gpg | apt-key add - && apt update

RUN apt install -y bazel-7.1.2

RUN ln -s /usr/bin/bazel-7.1.2 /usr/bin/bazel

WORKDIR /workspace

COPY . ./

RUN bazel build -c opt //tvs/untrusted_tvs:tvs-server_main

# TODO(alwabel): provide instructions on how to generate test keys.
CMD ["./bazel-bin/tvs/untrusted_tvs/tvs-server_main", \
     "--primary_private_key=0000000000000000000000000000000000000000000000000000000000000001", \
     "--appraisal_policy_file=tvs/test_data/on-perm-reference.textproto"]
