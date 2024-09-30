#!/bin/bash
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

echo "Creating single node openstack dev environment for '$USER'"
echo "Changing project to ps-hats-playground"
gcloud config set project ps-hats-playground

echo "Creating blank VM disk"
readonly ZONE='us-west4-b'

gcloud compute disks create "${USER}"-rocky-linux-9-disk \
    --image-project rocky-linux-cloud \
    --image-family rocky-linux-9 \
    --zone ${ZONE}

echo "Creating Nested Virtualization Image"
gcloud compute images create "${USER}"-rocky-linux-9-nested \
    --source-disk "${USER}"-rocky-linux-9-disk \
    --source-disk-zone "${ZONE}" \
    --licenses "https://www.googleapis.com/compute/v1/projects/vm-options/global/licenses/enable-vmx"

echo "Creating Nested Virtualization VM"
gcloud compute instances create "${USER}"-openstack-lab \
    --zone "${ZONE}" \
    --image "${USER}"-rocky-linux-9-nested \
    --boot-disk-size 200G \
    --boot-disk-type pd-ssd \
    --can-ip-forward \
    --network default \
    --tags http-server,https-server,novnc,openstack-apis \
    --min-cpu-platform "Intel Haswell" \
    --machine-type n1-standard-32

internal_ip=$(gcloud compute instances describe "${USER}"-openstack-lab \
    --zone ${ZONE} \
    --format='get(networkInterfaces[0].networkIP)')

external_ip=$(gcloud compute instances describe "${USER}"-openstack-lab \
    --zone ${ZONE} \
    --format='get(networkInterfaces[0].accessConfigs[0].natIP)')

echo "Cloud Internal IP: ${internal_ip}"
echo "Public IP: ${external_ip}"

echo "To connect to the newly created environment, run:"
echo "gcloud compute ssh ${USER}-openstack-lab --zone ${ZONE}"
