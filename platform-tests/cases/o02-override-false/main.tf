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

# O-02  The guardrail switched off at project level by setting enforce to
# FALSE. Gate: denied by the rule protecting the key-creation constraint.
# Platform: accepted for an identity holding the organisation policy
# administrator role. run.sh then shows that key creation succeeds.

resource "google_org_policy_policy" "o02" {
  name   = "projects/${var.project_id}/policies/iam.managed.disableServiceAccountKeyCreation"
  parent = "projects/${var.project_id}"
  spec {
    rules {
      enforce = "FALSE"
    }
  }
}
