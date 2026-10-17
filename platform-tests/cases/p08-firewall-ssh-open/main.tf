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

# P-08  CIS 3.6. A project firewall rule opening SSH to the internet.
# Gate: denied by the 3.6 rule. Platform: the rule is created, because no
# constraint refuses it, but the folder firewall policy denies the same traffic
# first. run.sh records the effective firewall view to show the order.

resource "google_compute_firewall" "p08" {
  name          = "p08-allow-ssh-anywhere"
  network       = "projects/${var.project_id}/global/networks/zt-test-net"
  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
