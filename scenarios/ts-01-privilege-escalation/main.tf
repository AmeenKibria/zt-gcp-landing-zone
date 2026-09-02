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

# ts-01  Compromised developer identity attempting privilege escalation
# NON-COMPLIANT by design. The pipeline must reject this plan.

resource "google_service_account" "platform" {
  account_id   = "platform-admin"
  display_name = "Platform administration"
  project      = var.project_id
}

# (1) A basic role at project level grants far more than any task needs.
resource "google_project_iam_member" "developer_owner" {
  project = var.project_id
  role    = "roles/owner"
  member  = "user:developer@example.com"
}

# (2) Token creation on a privileged account allows full impersonation.
resource "google_service_account_iam_member" "impersonate_platform_sa" {
  service_account_id = google_service_account.platform.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "user:developer@example.com"
}
