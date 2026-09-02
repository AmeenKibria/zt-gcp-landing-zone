package landingzone.storage

# Zero Trust tenet 2: all communication secured regardless of network location
# (Rose et al., 2020, pp. 6-7).
# CIS GCP Foundation Benchmark v5.0.0: 5.1, 5.2.

public_principals := {"allUsers", "allAuthenticatedUsers"}

# CIS 5.1 - buckets must not be anonymously or publicly accessible.
deny contains msg if {
  some change in input.resource_changes
  change.type == "google_storage_bucket_iam_member"
  public_principals[change.change.after.member]
  msg := sprintf("ts-03 [CIS 5.1]: bucket %v grants %v to %v", [change.change.after.bucket, change.change.after.role, change.change.after.member])
}

deny contains msg if {
  some change in input.resource_changes
  change.type == "google_storage_bucket"
  change.change.after.public_access_prevention != "enforced"
  msg := sprintf("ts-03 [CIS 5.1]: bucket %v does not set public_access_prevention = enforced", [change.change.after.name])
}

# CIS 5.2 - uniform bucket-level access must be enabled.
deny contains msg if {
  some change in input.resource_changes
  change.type == "google_storage_bucket"
  not change.change.after.uniform_bucket_level_access
  msg := sprintf("ts-03 [CIS 5.2]: bucket %v does not enable uniform_bucket_level_access", [change.change.after.name])
}
