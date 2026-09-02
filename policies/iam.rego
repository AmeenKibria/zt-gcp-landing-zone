package landingzone.iam

# MESSAGE CONVENTION
# A denial names the control it enforces and the security area it belongs to.
# It does not name a threat scenario. Rules are global: every rule is evaluated
# against every resource in whatever plan the pipeline is given, so a rule
# written with one scenario in mind fires wherever the condition holds. Tagging
# a rule with a scenario identifier asserts an ownership that does not exist.
# The scenario-to-rule mapping belongs in the evaluation, not in the policy.
#
# [design] marks a requirement of this landing zone that the CIS benchmark does
# not state. Those are deliberate additions, not gaps in the citation.

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
  msg := sprintf("[CIS 1.6] iam: basic role %v granted to %v; use a predefined or custom role", [role, change.change.after.member])
}

# CIS 1.7 - Service Account User / Token Creator must not be held at project level.
deny contains msg if {
  some change in input.resource_changes
  change.type == "google_service_account_iam_member"
  impersonation_roles[change.change.after.role]
  startswith(change.change.after.member, "user:")
  msg := sprintf("[CIS 1.7] iam: %v grants impersonation to human principal %v", [change.change.after.role, change.change.after.member])
}
