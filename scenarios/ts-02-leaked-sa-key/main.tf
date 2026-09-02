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

# The same scenario, approached from the other side. A downloaded key is the
# obvious way to hand out a long-lived credential. Misconfigured federation is
# the quiet way, and it hands out more.

resource "google_iam_workload_identity_pool" "loose" {
  project                   = var.project_id
  workload_identity_pool_id = "ts02-loose-pool"
  display_name              = "Loosely scoped pool"
}

# (2) A provider with no attribute_condition. Every repository the issuer will
#     sign for is accepted, not only the one this project belongs to.
resource "google_iam_workload_identity_pool_provider" "loose" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.loose.workload_identity_pool_id
  workload_identity_pool_provider_id = "ts02-loose-provider"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
  }

  # attribute_condition deliberately omitted

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

# (3) Impersonation granted to the whole pool rather than to one repository.
#     Any identity that can reach the provider above can now assume this account.
resource "google_service_account_iam_member" "pool_wide_impersonation" {
  service_account_id = google_service_account.workload.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.loose.name}/*"
}
