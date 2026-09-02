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

# ts-06  Secret in code, and data encrypted with a key the workload can decrypt
# NON-COMPLIANT by design.

resource "google_service_account" "workload" {
  account_id   = "data-reader"
  display_name = "Data reader"
  project      = var.project_id
}

resource "google_kms_key_ring" "core" {
  name     = "core-ring"
  location = var.region
  project  = var.project_id
}

# (1) A secret value written straight into the configuration.
resource "google_secret_manager_secret" "db_password" {
  secret_id = "clinical-db-password"
  project   = var.project_id

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "db_password" {
  secret      = google_secret_manager_secret.db_password.id
  secret_data = "Sup3rS3cret-2026!"
}

# (2) A key with no rotation period.
resource "google_kms_crypto_key" "clinical" {
  name     = "clinical-data-key"
  key_ring = google_kms_key_ring.core.id
  # rotation_period omitted
}

# (3) A data bucket left on Google-managed keys.
resource "google_storage_bucket" "clinical_data" {
  name                        = "${var.project_id}-clinical-data"
  location                    = "EU"
  project                     = var.project_id
  public_access_prevention    = "enforced"
  uniform_bucket_level_access = true
  # no encryption block
}

# (4) The Capital One pattern: the identity that reads the objects also holds
#     decrypt on the key protecting them (Khan et al., 2022, Section 3.2).
resource "google_kms_crypto_key_iam_member" "workload_decrypt" {
  crypto_key_id = google_kms_crypto_key.clinical.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_service_account.workload.email}"
}

resource "google_storage_bucket_iam_member" "workload_read" {
  bucket = google_storage_bucket.clinical_data.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.workload.email}"
}

# (5) The key itself made readable by anyone.
resource "google_kms_crypto_key_iam_member" "public_key_viewer" {
  crypto_key_id = google_kms_crypto_key.clinical.id
  role          = "roles/cloudkms.viewer"
  member        = "allUsers"
}
