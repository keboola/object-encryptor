terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.74"
    }

    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 2.98"
    }

    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.18"
    }

    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.9"
    }
  }
}

variable "name_prefix" {
  type = string
}
