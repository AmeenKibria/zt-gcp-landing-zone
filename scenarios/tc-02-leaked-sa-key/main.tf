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

# tc-02  Compliant twin of ts-02
# COMPLIANT by design. No key is created; federation is scoped.
#
# The binding names the existing bootstrap pool by its resource name. The project
# number is read with a data source so the member is known when the plan is made.
# A pool created in the same plan would leave the member unknown, and the gate
# denies an unknown scope by design.

data "google_project" "this" {
  project_id = var.project_id
}

resource "google_service_account" "workload" {
  account_id   = "workload-federated"
  display_name = "Workload authenticated by federation"
  project      = var.project_id
}

resource "google_iam_workload_identity_pool" "scoped" {
  project                   = var.project_id
  workload_identity_pool_id = "tc02-scoped-pool"
  display_name              = "Scoped pool"
}

# (1) The provider accepts tokens from one repository only.
resource "google_iam_workload_identity_pool_provider" "scoped" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.scoped.workload_identity_pool_id
  workload_identity_pool_provider_id = "tc02-scoped-provider"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
  }

  attribute_condition = "assertion.repository == \"AmeenKibria/zt-gcp-landing-zone\""

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

# (2) Impersonation is granted to one repository, not to the whole pool.
resource "google_service_account_iam_member" "repository_scoped" {
  service_account_id = google_service_account.workload.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/projects/${data.google_project.this.number}/locations/global/workloadIdentityPools/github-pool/attribute.repository/AmeenKibria/zt-gcp-landing-zone"
}
