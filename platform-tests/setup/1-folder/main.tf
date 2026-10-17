# Platform-layer test, stage 1: a test folder and the constraints set on it.
#
# The landing zone sets these constraints at organisation level. Here they are
# set on a dedicated test folder instead, so the test cannot affect anything
# else in the test organisation. A policy on a folder binds every project
# beneath it in the same way a policy on the organisation does.
#
# No identifier is committed. The organisation, billing account and quota
# project come from config.env through TF_VAR_* variables.

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

variable "org_id" {
  type = string
}

variable "quota_project" {
  type        = string
  description = "Existing project in the test organisation that carries API quota for user credentials."
}

variable "folder_name" {
  type    = string
  default = "zt-platform-test"
}

provider "google" {
  billing_project       = var.quota_project
  user_project_override = true
}

resource "google_folder" "test" {
  display_name        = var.folder_name
  parent              = "organizations/${var.org_id}"
  deletion_protection = false
}

locals {
  folder = google_folder.test.name # "folders/<number>"
}

# CIS 3.1: new projects get no default network. Must be in effect before the
# test project enables the Compute Engine API, which is why stage 2 waits.
resource "google_org_policy_policy" "skip_default_network" {
  name   = "${local.folder}/policies/compute.skipDefaultNetworkCreation"
  parent = local.folder
  spec {
    rules {
      enforce = "TRUE"
    }
  }
}

# CIS 4.9: no external IP addresses on VM instances (list constraint, deny all).
resource "google_org_policy_policy" "vm_external_ip" {
  name   = "${local.folder}/policies/compute.vmExternalIpAccess"
  parent = local.folder
  spec {
    rules {
      deny_all = "TRUE"
    }
  }
}

# CIS 4.6: no IP forwarding on VM instances (list constraint, deny all).
resource "google_org_policy_policy" "vm_ip_forward" {
  name   = "${local.folder}/policies/compute.vmCanIpForward"
  parent = local.folder
  spec {
    rules {
      deny_all = "TRUE"
    }
  }
}

# CIS 4.8: new VM instances must use Shielded VM.
resource "google_org_policy_policy" "shielded_vm" {
  name   = "${local.folder}/policies/compute.requireShieldedVm"
  parent = local.folder
  spec {
    rules {
      enforce = "TRUE"
    }
  }
}

# CIS 6.5 and 6.7: no public IP address on Cloud SQL instances.
resource "google_org_policy_policy" "sql_public_ip" {
  name   = "${local.folder}/policies/sql.restrictPublicIp"
  parent = local.folder
  spec {
    rules {
      enforce = "TRUE"
    }
  }
}

# CIS 5.2: uniform bucket-level access. Set explicitly so the result does not
# depend on whether the organisation received Google's baseline policies.
resource "google_org_policy_policy" "uniform_bucket_access" {
  name   = "${local.folder}/policies/storage.uniformBucketLevelAccess"
  parent = local.folder
  spec {
    rules {
      enforce = "TRUE"
    }
  }
}

# CIS 1.5: no user-managed service account keys (managed constraint form).
resource "google_org_policy_policy" "sa_key_creation" {
  name   = "${local.folder}/policies/iam.managed.disableServiceAccountKeyCreation"
  parent = local.folder
  spec {
    rules {
      enforce = "TRUE"
    }
  }
}

output "folder_id" {
  value = trimprefix(google_folder.test.name, "folders/")
}
