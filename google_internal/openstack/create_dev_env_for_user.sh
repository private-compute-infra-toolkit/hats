#!/bin/bash
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
