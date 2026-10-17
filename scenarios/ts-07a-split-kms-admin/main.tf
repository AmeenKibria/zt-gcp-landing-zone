terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

variable "project_id" {
  type    = string
  default = "zt-lz-sandbox"
}

variable "region" {
  type    = string
  default = "europe-north1"
}

# ts-07a  Split-plan case, first half
# Compliant on its own. Together with ts-07b it violates CIS 1.12: the same
# person administers a key and uses it. The gate reads one plan at a time, so
# neither half is denied. This scenario documents that limit; it is expected to
# pass.

resource "google_project_iam_member" "custodian_kms_admin" {
  project = var.project_id
  role    = "roles/cloudkms.admin"
  member  = "user:key-custodian-split@example.com"
}
