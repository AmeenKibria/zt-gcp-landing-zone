terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

variable "project_id" {
  type = string
}

variable "region" {
  type    = string
  default = "europe-north1"
}

variable "zone" {
  type    = string
  default = "europe-north1-a"
}

provider "google" {
  project               = var.project_id
  region                = var.region
  zone                  = var.zone
  billing_project       = var.project_id
  user_project_override = true
}

locals {
  subnet = "projects/${var.project_id}/regions/${var.region}/subnetworks/zt-test-subnet"
}

# P-02  CIS 5.2. A bucket without uniform bucket-level access.
# Gate: denied by the 5.2 rule and by the design rule asking for a
# customer-managed key. Platform: refused by storage.uniformBucketLevelAccess.

resource "google_storage_bucket" "p02" {
  name                        = "${var.project_id}-p02"
  location                    = var.region
  uniform_bucket_level_access = false
  public_access_prevention    = "enforced"
  force_destroy               = true
}
