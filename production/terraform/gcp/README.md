## Pre-requisites

1. Install Terraform
2. Install the gcloud CLI
   - https://cloud.google.com/sdk/docs/install
3. Configure the GCP credentials
   - https://cloud.google.com/sdk/docs/authorizing
4. Enable required GCP APIs
```
gcloud services enable \
    artifactregistry.googleapis.com \
    cloudkms.googleapis.com \
    iam.googleapis.com \
    spanner.googleapis.com \
    run.googleapis.com
 ```

 ## Instructions
 1. Create a new directory in environments directory and copy the contents of
   `environments/demo` to the new environment directory. The `environments/demo` contains the minimum setup needed for deploying an instance of the federated compute shuffler.
```bash
cp -avR environments/demo environments/<new_env>
```
2. Update file `main.tf`:
    - terraform configurations
        - uncomment the `backend "gcs"` block and populate:
           - bucket: gcs bucket to store the terraform state
           - prefix: prefix of the path to store the terraform state
3. (Optional) rename the `demo.auto.tfvars` file to use the new environment name `<new_env>.auto.tfvars`
4. Populate the required fields in `<new_env>.auto.tfvars`
5. Apply the terraform:
```bash
terraform init
terraform apply -auto-approve
```
