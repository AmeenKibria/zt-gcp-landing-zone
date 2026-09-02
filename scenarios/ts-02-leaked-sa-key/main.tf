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

# ts-02  Leaked service account key
# NON-COMPLIANT by design.

resource "google_service_account" "workload" {
  account_id   = "workload-runner"
  display_name = "Workload runner"
  project      = var.project_id
}

# A user-managed key never expires and can be copied anywhere once downloaded.
resource "google_service_account_key" "workload_key" {
  service_account_id = google_service_account.workload.name
  private_key_type   = "TYPE_GOOGLE_CREDENTIALS_FILE"
}
