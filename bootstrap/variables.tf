variable "project_id" {
  description = "Sandbox project ID. Appears in thesis screenshots, so keep it neutral."
  type        = string
  default     = "zt-lz-sandbox"
}

variable "region" {
  description = "Default region."
  type        = string
  default     = "europe-north1"
}

variable "github_repository" {
  description = "Repository allowed to authenticate, as owner/name."
  type        = string
  default     = "AmeenKibria/zt-gcp-landing-zone"
}
