# Platform-layer test, stage 2: the test project under the test folder, the APIs
# the cases need, one network for the VM cases, and a hierarchical firewall
# policy on the folder.
#
# Run only after the stage 1 constraints have propagated (up to 15 minutes,
# per the Organization Policy documentation). The default network is created,
# or not, at the moment the Compute Engine API is enabled below.

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

variable "folder_id" {
  type = string
}

variable "project_id" {
  type = string
}

variable "billing_account" {
  type = string
}

variable "quota_project" {
  type = string
}

variable "region" {
  type    = string
  default = "europe-north1"
}

# Project creation and API enablement are billed to the existing quota project.
provider "google" {
  billing_project       = var.quota_project
  user_project_override = true
}

# Compute resources, including the folder's firewall policy, are billed to the
# test project once its Compute Engine API is on.
provider "google" {
  alias                 = "test"
  project               = var.project_id
  region                = var.region
  billing_project       = var.project_id
  user_project_override = true
}

resource "google_project" "test" {
  name            = "zt platform test"
  project_id      = var.project_id
  folder_id       = var.folder_id
  billing_account = var.billing_account
  # true means Terraform does not delete a default network itself. If none
  # exists afterwards, the folder constraint is what prevented it (CIS 3.1).
  auto_create_network = true
  deletion_policy     = "DELETE"
}

resource "google_project_service" "apis" {
  for_each = toset([
    "compute.googleapis.com",
    "iam.googleapis.com",
    "sqladmin.googleapis.com",
    "storage.googleapis.com",
    "cloudasset.googleapis.com",
    "policysimulator.googleapis.com",
    "orgpolicy.googleapis.com",
    "cloudresourcemanager.googleapis.com",
  ])
  project            = google_project.test.project_id
  service            = each.value
  disable_on_destroy = false
}

# One network for the VM cases. Its subnet logs flows with the benchmark's
# settings, so the gate has nothing to say about it.
resource "google_compute_network" "test" {
  provider                = google.test
  name                    = "zt-test-net"
  auto_create_subnetworks = false
  depends_on              = [google_project_service.apis]
}

resource "google_compute_subnetwork" "test" {
  provider      = google.test
  name          = "zt-test-subnet"
  network       = google_compute_network.test.id
  ip_cidr_range = "10.80.0.0/24"
  region        = var.region

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 1.0
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# CIS 3.6 and 3.7 at the platform: SSH and RDP from anywhere are denied by a
# hierarchical policy on the folder. A matching deny ends evaluation, so a
# project's own VPC firewall rules are never reached for that traffic.
resource "google_compute_firewall_policy" "test" {
  provider    = google.test
  parent      = "folders/${var.folder_id}"
  short_name  = "zt-platform-test-baseline"
  description = "Baseline deny for administrative ports (platform-layer test)"
  depends_on  = [google_project_service.apis]
}

resource "google_compute_firewall_policy_rule" "deny_admin_ports" {
  provider        = google.test
  firewall_policy = google_compute_firewall_policy.test.name
  priority        = 1000
  direction       = "INGRESS"
  action          = "deny"
  description     = "SSH and RDP from any source"

  match {
    src_ip_ranges = ["0.0.0.0/0"]
    layer4_configs {
      ip_protocol = "tcp"
      ports       = ["22", "3389"]
    }
  }
}

resource "google_compute_firewall_policy_association" "test" {
  provider          = google.test
  name              = "zt-platform-test-association"
  firewall_policy   = google_compute_firewall_policy.test.id
  attachment_target = "folders/${var.folder_id}"
}

output "project_number" {
  value = google_project.test.number
}
