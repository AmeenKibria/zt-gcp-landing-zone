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

# tc-01  Compliant twin of ts-01
# COMPLIANT by design. The gate must let this plan through with no denial.

resource "google_service_account" "platform" {
  account_id   = "platform-ops"
  display_name = "Platform operations"
  project      = var.project_id
}

# (1) The developer reads the hierarchy and nothing more.
resource "google_project_iam_member" "developer_browser" {
  project = var.project_id
  role    = "roles/browser"
  member  = "user:developer@example.com"
}

# (2) Emergency impersonation is held by a group, on one account.
resource "google_service_account_iam_member" "emergency_group" {
  service_account_id = google_service_account.platform.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "group:platform-emergency@example.com"
}

# (3) The account holds a bounded predefined role, not an admin role.
resource "google_project_iam_member" "platform_sa_bounded" {
  project = var.project_id
  role    = "roles/logging.viewer"
  member  = "serviceAccount:${google_service_account.platform.email}"
}
