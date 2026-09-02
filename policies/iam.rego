package landingzone.iam

# Zero Trust tenet 3: access granted per session, with least privilege
# (Rose et al., 2020, pp. 6-7).
# CIS GCP Foundation Benchmark v5.0.0: 1.6, 1.7, 1.9.

basic_roles := {"roles/owner", "roles/editor", "roles/viewer"}

impersonation_roles := {
  "roles/iam.serviceAccountTokenCreator",
  "roles/iam.serviceAccountUser",
}

# CIS 1.6 - service accounts must not hold admin privileges.
deny contains msg if {
  some change in input.resource_changes
  change.type == "google_project_iam_member"
  role := change.change.after.role
  basic_roles[role]
  msg := sprintf("ts-01 [CIS 1.6]: basic role %v granted to %v; use a predefined or custom role", [role, change.change.after.member])
}

# CIS 1.7 - Service Account User / Token Creator must not be held at project level.
deny contains msg if {
  some change in input.resource_changes
  change.type == "google_service_account_iam_member"
  impersonation_roles[change.change.after.role]
  startswith(change.change.after.member, "user:")
  msg := sprintf("ts-01 [CIS 1.7]: %v grants impersonation to human principal %v", [change.change.after.role, change.change.after.member])
}
