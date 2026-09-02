output "workload_identity_provider" {
  description = "Set as the WIF_PROVIDER Actions variable."
  value       = google_iam_workload_identity_pool_provider.github.name
}

output "pipeline_service_account" {
  description = "Set as the WIF_SERVICE_ACCOUNT Actions variable."
  value       = google_service_account.pipeline.email
}
