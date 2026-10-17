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

# tc-03  Compliant twin of ts-03
# COMPLIANT by design. The bucket is private, uniform and encrypted with a
# customer-managed key; readers are a named group.

data "google_project" "this" {
  project_id = var.project_id
}

resource "google_kms_key_ring" "reports" {
  name     = "tc03-reports-ring"
  location = var.region
  project  = var.project_id
}

resource "google_kms_crypto_key" "reports" {
  name            = "tc03-reports-key"
  key_ring        = google_kms_key_ring.reports.id
  rotation_period = "7776000s"
}

resource "google_storage_bucket" "reports" {
  name                        = "${var.project_id}-tc03-reports-export"
  location                    = upper(var.region)
  project                     = var.project_id
  public_access_prevention    = "enforced"
  uniform_bucket_level_access = true

  encryption {
    default_kms_key_name = google_kms_crypto_key.reports.id
  }

  versioning {
    enabled = true
  }
}

resource "google_storage_bucket_iam_member" "group_read" {
  bucket = google_storage_bucket.reports.name
  role   = "roles/storage.objectViewer"
  member = "group:clinical-reporting@example.com"
}

# The Cloud Storage service agent needs encrypt and decrypt on the key for a
# customer-managed key to work. It holds no object read role, so it is not the
# read-plus-decrypt pattern.
resource "google_kms_crypto_key_iam_member" "storage_agent" {
  crypto_key_id = google_kms_crypto_key.reports.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.this.number}@gs-project-accounts.iam.gserviceaccount.com"
}
