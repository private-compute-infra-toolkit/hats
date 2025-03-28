# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Image tags and digests are found at https://hub.docker.com/_/ubuntu/tags
ARG image_digest=sha256:72297848456d5d37d1262630108ab308d3e9ec7ed1c3286a32fe09856619a782
FROM ubuntu:latest@${image_digest}

RUN apt-get update && apt-get install --no-install-recommends --yes python3 \
       curl ca-certificates git gnupg2 patch pre-commit shellcheck nix

RUN echo 'experimental-features = nix-command flakes' >> /etc/nix/nix.conf

# Make nix use the default profile for the current user.
ENV PATH=/nix/var/nix/profiles/default/bin/:$PATH

# Required to install bazel.
RUN echo "deb [arch=amd64] http://storage.googleapis.com/bazel-apt stable jdk1.8" \
	 | tee /etc/apt/sources.list.d/bazel.list

RUN curl https://bazel.build/bazel-release.pub.gpg \
	| apt-key add - && apt-get update

RUN apt-get install -y bazel-7.4.1

RUN ln -s /usr/bin/bazel-7.4.1 /usr/bin/bazel
