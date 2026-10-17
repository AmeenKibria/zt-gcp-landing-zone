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

# ts-07b  Split-plan case, second half
# Compliant on its own. Grants encrypt and decrypt on an existing key to the
# person who, in ts-07a, receives Cloud KMS Admin in a separate change. The key
# is named by its resource identifier because it is not created here.

resource "google_kms_crypto_key_iam_member" "custodian_use" {
  crypto_key_id = "projects/${var.project_id}/locations/${var.region}/keyRings/split-ring/cryptoKeys/split-key"
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "user:key-custodian-split@example.com"
}
