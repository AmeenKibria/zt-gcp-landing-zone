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

# P-04  CIS 4.6. A VM instance that forwards IP traffic.
# Gate: silent. Platform: refused by compute.vmCanIpForward.

resource "google_compute_instance" "p04" {
  name           = "p04-ip-forward"
  can_ip_forward = true
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
