locals {
  gcp_project = "keboola-dev-platform-services"
}

provider "google" {
  project = local.gcp_project
}
