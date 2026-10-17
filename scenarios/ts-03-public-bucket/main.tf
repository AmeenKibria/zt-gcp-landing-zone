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

# ts-03  Publicly reachable storage bucket
# NON-COMPLIANT by design.

resource "google_storage_bucket" "reports" {
  name     = "${var.project_id}-clinical-reports-export"
  location = "EU"
  project  = var.project_id

  # public_access_prevention defaults to "inherited", not "enforced".
  # uniform_bucket_level_access defaults to false, leaving object ACLs live.
  # Both omissions are the defect.

  versioning {
    enabled = false
  }
}

resource "google_storage_bucket_iam_member" "public_read" {
  bucket = google_storage_bucket.reports.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}
