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

# C-01  Compliant twin at the platform layer. No external address, no
# forwarding, all Shielded VM features on. Gate: silent. Platform: created,
# which shows that the refusals in P-03 to P-05 come from the constraints and
# not from quota, permissions or a disabled API. run.sh deletes it at once.

resource "google_compute_instance" "c01" {
  name         = "c01-compliant"
  machine_type = "e2-micro"
  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }
  network_interface {
    subnetwork = local.subnet
  }
  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }
}
