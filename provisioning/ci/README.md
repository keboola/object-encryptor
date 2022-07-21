# CI provisioning

### Prepare necessary AWS resources
Run the `prepare-aws-resources.sh` script using `CI-Platform-Services-Team` account (use
`Keboola-CI-Platform-Services-Team-AWSAdministratorAccess` profile). The script prepares resources needed for Terraform
remote backend and user account to use in CI.

### Prepare cloud resources
Initialize & run Terraform to create resources for CI. Notice no `tfstate` file is created, it's actually automatically
saved to the remote S3 bucket si it can be accessed by the CI pipeline later.

```bash
terraform init -backend-config=./s3.tfbackend 
terraform apply 
```

Then take the results from the terraform command and configure them manually in `push.yml`. Secrets are configured in 
GitHub repository secrets.

## Ongoing updates
As the CI does not apply changes (only uses existing state), anytime you change anything, you have to apply changes
locally.

```bash
terraform init -backend-config=./s3.tfbackend
terraform apply
```

The reason why we do not apply changes automatically in CI is:
* to run Terraform you need to have pretty high privileges in infra to create all the resources, this way don't need to
  give such privileges to the CI.
* if you add some new resources in a branch, the branch CI run would create the resource. Then if you run CI for other
  branch, it would destroy the resource again and so on.
 