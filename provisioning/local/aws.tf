provider "aws" {
  profile = "keboola-dev-platform-services"
  region  = "eu-central-1"

  default_tags {
    tags = {
      KebolaStack = "${var.name_prefix}-object-encryptor"
      KeboolaRole = "object-encryptor"
    }
  }
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

output "aws_region" {
  value = data.aws_region.current.id
}
