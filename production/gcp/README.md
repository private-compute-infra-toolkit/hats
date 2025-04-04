# Building TVS image for Google Cloud

## Prerequisites

### Set up GCloud CLI

Make sure you [install](https://cloud.google.com/sdk/gcloud) and
[authenticate](https://cloud.google.com/sdk/docs/authorizing#auth-login) the latest gcloud CLI.

### Create a Docker image repo under Google Cloud Artifact Registry

If you haven't done so, create a Docker image repo under Google Cloud Artifact Registry. Instructions
can be found [here](https://cloud.google.com/artifact-registry/docs/repositories/create-repos).
This will be used for uploading the Docker image for the TVS.

## Building the TVS image

To trigger the artifacts build, run the following command from the root of the repo:

```sh
gcloud builds submit --config=production/gcp/cloudbuild.yaml --substitutions=_OUTPUT_IMAGE_REPO_PATH="<YourOutputContainerRegistryRepoPath>",_OUTPUT_IMAGE_TAG="<YourOutputImageCustomTag>"
```

The build can take several minutes. You can check the status at
`https://console.cloud.google.com/cloud-build/builds`.
