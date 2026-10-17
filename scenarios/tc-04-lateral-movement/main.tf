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

# tc-04  Compliant twin of ts-04
# COMPLIANT by design. Administrative access arrives only from Identity-Aware
# Proxy's range, the workload holds a read-only role, and the subnet logs every
# flow with the benchmark's settings.

resource "google_service_account" "workload" {
  account_id   = "workload-b"
  display_name = "Workload B"
  project      = var.project_id
}

resource "google_compute_network" "workload" {
  name                    = "tc04-workload-net"
  project                 = var.project_id
  auto_create_subnetworks = false
}

resource "google_compute_firewall" "allow_ssh_iap" {
  name      = "tc04-allow-ssh-from-iap"
  network   = google_compute_network.workload.name
  project   = var.project_id
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["35.235.240.0/20"]
}

resource "google_project_iam_member" "workload_reader" {
  project = var.project_id
  role    = "roles/compute.viewer"
  member  = "serviceAccount:${google_service_account.workload.email}"
}

resource "google_compute_subnetwork" "workload_logged" {
  name          = "tc04-workload-subnet"
  network       = google_compute_network.workload.id
  ip_cidr_range = "10.30.0.0/24"
  region        = var.region
  project       = var.project_id

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 1.0
    metadata             = "INCLUDE_ALL_METADATA"
  }
}
