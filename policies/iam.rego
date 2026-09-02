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

# CIS 1.6 is titled "Ensure That Service Account Has No Admin Privileges", so
# the rule that cites it covers the two basic roles that confer admin. Read-only
# is handled separately below, under [design], because the benchmark does not
# reach it and this policy set should not claim that it does.
admin_basic_roles := {"roles/owner", "roles/editor"}

impersonation_roles := {
  "roles/iam.serviceAccountTokenCreator",
  "roles/iam.serviceAccountUser",
}

# CIS 1.6 - no principal may hold admin privileges through a basic role.
deny contains msg if {
  some change in input.resource_changes
  change.type == "google_project_iam_member"
  role := change.change.after.role
  admin_basic_roles[role]
  msg := sprintf("[CIS 1.6] iam: basic role %v granted to %v; use a predefined or custom role", [role, change.change.after.member])
}

# Beyond the benchmark. roles/viewer confers no admin privilege, so CIS 1.6 does
# not reach it. Its scope is nonetheless unbounded, and it widens on its own as
# Google adds services to the platform, so a principal granted it today holds
# read access to resource types that did not exist when the grant was reviewed.
# This landing zone grants roles/browser plus bounded predefined roles instead.
deny contains msg if {
  some change in input.resource_changes
  change.type == "google_project_iam_member"
  change.change.after.role == "roles/viewer"
  msg := sprintf("[design] iam: roles/viewer granted to %v; its scope is unbounded, use roles/browser or a bounded predefined role", [change.change.after.member])
}

# CIS 1.7 - Service Account User and Token Creator must not be held at project
# level. A project-level grant confers impersonation over every service account
# in the project, present and future, which is what the benchmark prohibits.
deny contains msg if {
  some change in input.resource_changes
  change.type == "google_project_iam_member"
  impersonation_roles[change.change.after.role]
  startswith(change.change.after.member, "user:")
  msg := sprintf("[CIS 1.7] iam: %v granted at project level to %v; it confers impersonation over every service account in the project", [change.change.after.role, change.change.after.member])
}

# Beyond the benchmark. A grant scoped to one service account is outside CIS 1.7,
# which addresses project-level grants only. This landing zone denies it to human
# principals anyway: a person who can act as a service account has a path to
# change infrastructure that does not pass through the pipeline, which is the
# escalation the design exists to remove.
#
# The same grant to a service account is deliberately NOT denied. The pipeline
# impersonates a task-scoped service account for each job, and that chain is the
# mechanism by which least privilege is applied per job rather than per pipeline.
deny contains msg if {
  some change in input.resource_changes
  change.type == "google_service_account_iam_member"
  impersonation_roles[change.change.after.role]
  startswith(change.change.after.member, "user:")
  msg := sprintf("[design] iam: %v grants impersonation to human principal %v; humans have no path to act as automation", [change.change.after.role, change.change.after.member])
}
