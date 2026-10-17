terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
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

# tc-06  Compliant twin of ts-06
# COMPLIANT by design. The secret value is produced at apply time, the key
# rotates at exactly the 90-day limit and is not public, the bucket uses the key,
# and key administration, key use and object read are held by different parties.

data "google_project" "this" {
  project_id = var.project_id
}

resource "google_service_account" "workload" {
  account_id   = "data-reader-ok"
  display_name = "Data reader"
  project      = var.project_id
}

resource "google_kms_key_ring" "core" {
  name     = "tc06-core-ring"
  location = var.region
  project  = var.project_id
}

# (1) Boundary case: 7776000 seconds is exactly 90 days, which the benchmark allows.
resource "google_kms_crypto_key" "clinical" {
  name            = "tc06-clinical-data-key"
  key_ring        = google_kms_key_ring.core.id
  rotation_period = "7776000s"
}

# (2) The secret value never appears in the configuration or the plan.
resource "random_password" "db" {
  length  = 32
  special = true
}

resource "google_secret_manager_secret" "db_password" {
  secret_id = "tc06-clinical-db-password"
  project   = var.project_id

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "db_password" {
  secret      = google_secret_manager_secret.db_password.id
  secret_data = random_password.db.result
}

# (3) The data bucket uses the customer-managed key.
resource "google_storage_bucket" "clinical_data" {
  name                        = "${var.project_id}-tc06-clinical-data"
  location                    = upper(var.region)
  project                     = var.project_id
  public_access_prevention    = "enforced"
  uniform_bucket_level_access = true

  encryption {
    default_kms_key_name = google_kms_crypto_key.clinical.id
  }
}

# (4) The workload reads objects and holds no decrypt role.
resource "google_storage_bucket_iam_member" "workload_read" {
  bucket = google_storage_bucket.clinical_data.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.workload.email}"
}

# (5) The custodian administers keys and does not use them.
resource "google_project_iam_member" "custodian_kms_admin" {
  project = var.project_id
  role    = "roles/cloudkms.admin"
  member  = "user:key-custodian@example.com"
}

# (6) Decrypt is held by the Cloud Storage service agent, which reads no objects
#     through IAM.
resource "google_kms_crypto_key_iam_member" "storage_agent" {
  crypto_key_id = google_kms_crypto_key.clinical.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.this.number}@gs-project-accounts.iam.gserviceaccount.com"
}
