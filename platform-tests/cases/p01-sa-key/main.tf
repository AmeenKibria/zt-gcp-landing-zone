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

# P-01  CIS 1.5. A user-managed service account key.
# Gate: denied by the 1.5 rule. Platform: the account is created and the key
# is refused by the folder constraint iam.managed.disableServiceAccountKeyCreation.

resource "google_service_account" "p01" {
  account_id   = "p01-key-test"
  display_name = "P-01 key test"
}

resource "google_service_account_key" "p01" {
  service_account_id = google_service_account.p01.name
}
