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

 # Instructions
 ## Setup
 1. Create a new directory in environments directory and copy the contents of
   `environments/demo` to the new environment directory. The `environments/demo` contains the minimum setup needed for deploying an instance of the federated compute shuffler.
```bash
cp -avR environments/demo environments/<new_env>
```

## Deploy tvs_db
1. Update file `main.tf`:
    - terraform configurations
        - uncomment the `backend "gcs"` block and populate:
           - bucket: gcs bucket to store the terraform state
           - prefix: prefix of the path to store the terraform state
2. (Optional) rename the `demo.auto.tfvars` file to use the new environment name `<new_env>.auto.tfvars`
3. Populate the required fields in `<new_env>.auto.tfvars`
4. Apply the terraform:
```bash
terraform init
terraform apply -auto-approve
```
5. Store output to be used for following steps
6. Populate Spanner with required data:
- [SQL Schema using Liquibase](../../gcp/README.md)
- [Appraisal policies and TVS keys](../../README.md)

## Deploy tvs
Before deploying [build the TVS image and push to Artifact Registry](../../gcp/README.md).

1. Update file `main.tf`:
    - terraform configurations
        - uncomment the `backend "gcs"` block and populate:
            - bucket: gcs bucket to store the terraform state
            - prefix: prefix of the path to store the terraform state
2. (Optional) rename the `demo.auto.tfvars` file to use the new environment name `<new_env>.auto.tfvars`
3. Populate the required fields in `<new_env>.auto.tfvars`
   - Pass fields from `tvs_db` output
4. Apply the terraform:
```bash
terraform init
terraform apply -auto-approve
```
