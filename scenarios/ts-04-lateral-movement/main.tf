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

# ts-04  Lateral movement between workloads after one compromise
# NON-COMPLIANT by design.

resource "google_service_account" "workload" {
  account_id   = "workload-a"
  display_name = "Workload A"
  project      = var.project_id
}

resource "google_compute_network" "workload" {
  name                    = "workload-net"
  project                 = var.project_id
  auto_create_subnetworks = false
}

# (1) Administrative ports open to the whole internet.
resource "google_compute_firewall" "allow_ssh_world" {
  name    = "allow-ssh-from-anywhere"
  network = google_compute_network.workload.name
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["22", "3389"]
  }

  source_ranges = ["0.0.0.0/0"]
}

# (2) A workload identity holding a broad admin role, so one compromise reaches
#     well beyond the workload it belongs to.
resource "google_project_iam_member" "workload_compute_admin" {
  project = var.project_id
  role    = "roles/compute.admin"
  member  = "serviceAccount:${google_service_account.workload.email}"
}
