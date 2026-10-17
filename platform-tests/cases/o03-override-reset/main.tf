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

# O-03  The same guardrail switched off by resetting the project policy to
# the constraint default instead of setting enforce to FALSE. Plan only.
# Expected: the gate is silent, because the rule reads enforce = FALSE alone.
# Recorded as a known gap, written down before the run.

resource "google_org_policy_policy" "o03" {
  name   = "projects/${var.project_id}/policies/iam.managed.disableServiceAccountKeyCreation"
  parent = "projects/${var.project_id}"
  spec {
    reset = true
  }
}
