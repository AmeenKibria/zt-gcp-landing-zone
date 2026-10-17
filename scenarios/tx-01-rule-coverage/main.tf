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

# tx-01  Rule-coverage fixture
# NOT a threat scenario. It holds one instance of each rule condition that the
# six threat scenarios do not reach, so that every rule is observed against a
# real plan rather than only against hand-written test input. Several earlier
# defects were assumptions about the shape of the plan; this is where such an
# assumption would show. Expected to be denied; expected.txt lists each denial.
#
# Not included: the rule for a secret value that is withheld from the plan but
# known at plan time. Terraform 1.9.8 writes sensitive values into the plan in
# clear text, so that plan shape does not occur here. The rule is unit-tested.

# (1) CIS 1.5: switching off the key-creation constraint. `spec` is a nested
#     block; an earlier rule read it as an object and could never fire.
resource "google_org_policy_policy" "key_creation_off" {
  name   = "projects/${var.project_id}/policies/iam.disableServiceAccountKeyCreation"
  parent = "projects/${var.project_id}"

  spec {
    rules {
      enforce = "FALSE"
    }
  }
}

# (2) CIS 1.7: impersonation at project level, granted to a group.
resource "google_project_iam_member" "project_token_creator" {
  project = var.project_id
  role    = "roles/iam.serviceAccountTokenCreator"
  member  = "group:platform-emergency@example.com"
}

# (3) Design: roles/viewer.
resource "google_project_iam_member" "auditor_viewer" {
  project = var.project_id
  role    = "roles/viewer"
  member  = "user:auditor@example.com"
}

# (4) Design: impersonation granted to every identity in a pool. The project
#     number is a placeholder; the rule reads only the scope of the member.
resource "google_service_account" "federated" {
  account_id   = "tx01-federated"
  display_name = "Coverage fixture"
  project      = var.project_id
}

resource "google_service_account_iam_member" "pool_wide_known" {
  service_account_id = google_service_account.federated.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/projects/000000000000/locations/global/workloadIdentityPools/github-pool/*"
}

# (5) CIS 1.11: a rotation period longer than 90 days (365 days).
resource "google_kms_key_ring" "coverage" {
  name     = "tx01-coverage-ring"
  location = var.region
  project  = var.project_id
}

resource "google_kms_crypto_key" "long_rotation" {
  name            = "tx01-long-rotation-key"
  key_ring        = google_kms_key_ring.coverage.id
  rotation_period = "31536000s"
}

# (6) CIS 5.1 through a binding rather than a member. The bucket itself is
#     otherwise compliant, so only the binding is denied.
resource "google_storage_bucket" "binding_check" {
  name                        = "${var.project_id}-tx01-binding-check"
  location                    = upper(var.region)
  project                     = var.project_id
  public_access_prevention    = "enforced"
  uniform_bucket_level_access = true

  encryption {
    default_kms_key_name = google_kms_crypto_key.long_rotation.id
  }
}

resource "google_storage_bucket_iam_binding" "public_binding" {
  bucket  = google_storage_bucket.binding_check.name
  role    = "roles/storage.objectViewer"
  members = ["allUsers"]
}

# (7) CIS 3.6 through a port range that contains 22.
resource "google_compute_network" "coverage" {
  name                    = "tx01-coverage-net"
  project                 = var.project_id
  auto_create_subnetworks = false
}

resource "google_compute_firewall" "range_world" {
  name    = "tx01-allow-range-world"
  network = google_compute_network.coverage.name
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["20-30"]
  }

  source_ranges = ["0.0.0.0/0"]
}

# (8) Design: a database port open to the internet.
resource "google_compute_firewall" "postgres_world" {
  name    = "tx01-allow-postgres-world"
  network = google_compute_network.coverage.name
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["5432"]
  }

  source_ranges = ["0.0.0.0/0"]
}

# (9) CIS 3.10: flow logs present but sampling left at the provider default.
resource "google_compute_subnetwork" "sampled" {
  name          = "tx01-subnet-sampled"
  network       = google_compute_network.coverage.id
  ip_cidr_range = "10.40.0.0/24"
  region        = var.region
  project       = var.project_id

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    metadata             = "INCLUDE_ALL_METADATA"
  }
}
