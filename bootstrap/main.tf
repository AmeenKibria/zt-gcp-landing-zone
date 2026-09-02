# Bootstrap: let GitHub Actions authenticate to GCP without a downloaded key.
#
# Run this ONCE, by hand, with your own credentials. Everything after it runs
# through the pipeline. The policy set denies google_service_account_key
# (scenario ts-02), so the pipeline enforcing that rule must not use one either.

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

# --- identity pool for external (GitHub) identities -------------------------

resource "google_iam_workload_identity_pool" "github" {
  project                   = var.project_id
  workload_identity_pool_id = "github-pool"
  display_name              = "GitHub Actions"
  description               = "External identities from GitHub Actions OIDC"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-provider"
  display_name                       = "GitHub OIDC"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
    "attribute.ref"        = "assertion.ref"
  }

  # Without this condition ANY GitHub repository could exchange a token here.
  attribute_condition = "assertion.repository == \"${var.github_repository}\""

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

# --- the identity the pipeline assumes --------------------------------------

resource "google_service_account" "pipeline" {
  project      = var.project_id
  account_id   = "zt-pipeline"
  display_name = "Zero Trust landing zone pipeline"
}

resource "google_service_account_iam_member" "github_impersonation" {
  service_account_id = google_service_account.pipeline.name
  role               = "roles/iam.workloadIdentityUser"
  member = join("", [
    "principalSet://iam.googleapis.com/",
    google_iam_workload_identity_pool.github.name,
    "/attribute.repository/",
    var.github_repository,
  ])
}

# The pipeline never applies anything, so it needs only enough read access for
# the provider to resolve the project and plan a set of creates.
#
# roles/viewer was the obvious choice and it is the wrong one. The policy set
# denies every basic role, roles/viewer included (iam.rego, CIS 1.6). Granting
# it here would give the artifact a role its own gate forbids, and the only
# reason that never surfaced is that the bootstrap is applied by hand and never
# passes through the gate. That is the bootstrap trust problem, not a reason to
# keep the role.
#
# roles/browser is predefined rather than basic. It grants read access to the
# resource hierarchy without access to the resources inside it.
resource "google_project_iam_member" "pipeline_browser" {
  project = var.project_id
  role    = "roles/browser"
  member  = "serviceAccount:${google_service_account.pipeline.email}"
}
