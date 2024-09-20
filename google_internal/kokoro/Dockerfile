# Image tags and digests are found at https://hub.docker.com/_/ubuntu/tags
ARG image_digest=sha256:dfc10878be8d8fc9c61cbff33166cb1d1fe44391539243703c72766894fa834a
FROM ubuntu:latest@${image_digest}

RUN apt-get update && apt-get install --no-install-recommends --yes python3 \
		      curl ca-certificates git gnupg2 patch

# Required to install bazel.
RUN echo "deb [arch=amd64] http://storage.googleapis.com/bazel-apt stable jdk1.8" \
	 | tee /etc/apt/sources.list.d/bazel.list

RUN curl https://bazel.build/bazel-release.pub.gpg | apt-key add - && apt update

RUN apt install -y bazel-7.1.2

RUN ln -s /usr/bin/bazel-7.1.2 /usr/bin/bazel
