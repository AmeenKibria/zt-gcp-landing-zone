package landingzone.credentials

# Zero Trust tenet 6: authentication and authorisation dynamic and strictly
# enforced (Rose et al., 2020, pp. 6-7). A static exported key is neither.
# CIS GCP Foundation Benchmark v5.0.0: 1.5, 1.8.

# CIS 1.5 - only GCP-managed service account keys should exist.
deny contains msg if {
  some change in input.resource_changes
  change.type == "google_service_account_key"
  # service_account_id references another resource, so it is unknown at plan
  # time. The address identifies the offending resource without it.
  msg := sprintf("ts-02 [CIS 1.5]: %v creates a user-managed service account key; use identity federation", [change.address])
}

# Do not let the guardrail itself be switched off.
deny contains msg if {
  some change in input.resource_changes
  change.type == "google_org_policy_policy"
  contains(change.change.after.name, "iam.disableServiceAccountKeyCreation")
  some rule in change.change.after.spec.rules
  rule.enforce == "FALSE"
  msg := "ts-02 [CIS 1.5]: constraint iam.disableServiceAccountKeyCreation is being turned off"
}
