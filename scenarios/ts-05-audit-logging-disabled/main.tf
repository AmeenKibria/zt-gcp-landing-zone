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

# ts-05  Insider narrowing or disabling audit logging
# NON-COMPLIANT by design.

# Only ADMIN_READ is configured. DATA_READ and DATA_WRITE are absent, so reads
# and writes against data leave no audit trail.
resource "google_project_iam_audit_config" "partial" {
  project = var.project_id
  service = "allServices"

  audit_log_config {
    log_type = "ADMIN_READ"
  }
}

# An exemption removing a service account from data-access logging entirely.
resource "google_project_iam_audit_config" "exempted" {
  project = var.project_id
  service = "storage.googleapis.com"

  audit_log_config {
    log_type         = "DATA_READ"
    exempted_members = ["serviceAccount:platform@${var.project_id}.iam.gserviceaccount.com"]
  }
}
