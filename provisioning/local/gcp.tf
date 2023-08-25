provider "google" {
  project = var.gcp_project
}

output "gcp_project_id" {
  value = var.gcp_project
}
