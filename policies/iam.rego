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

# IMPERSONATION
#
# This landing zone relies on impersonation rather than on standing permissions,
# so the rules below draw a line through it rather than around it.
#
#   service account -> service account   permitted. The pipeline assumes a
#                                        task-scoped account for each job.
#   group -> service account             permitted. A named group holds the
#                                        emergency path into one service
#                                        project. The grant is standing, but
#                                        holding it confers nothing until a
#                                        token is minted, and minting one is
#                                        recorded against the person who did it.
#   individual -> service account        denied. A binding to one person is a
#                                        permission that no membership review
#                                        will ever surface.
#   anyone -> project level              denied. CIS 1.7.

# CIS 1.7 - Service Account User and Token Creator must not be held at project
# level, where they confer impersonation over every service account in the
# project, present and future.
#
# The benchmark says "IAM Users". This rule reads a group of users as covered,
# because a project-level grant to a group has the same effect as the same grant
# to each of its members. The interpretation is stated rather than assumed.
deny contains msg if {
  some change in input.resource_changes
  change.type == "google_project_iam_member"
  impersonation_roles[change.change.after.role]
  human_principal(change.change.after.member)
  msg := sprintf("[CIS 1.7] iam: %v granted at project level to %v; it confers impersonation over every service account in the project", [change.change.after.role, change.change.after.member])
}

# Beyond the benchmark. A grant scoped to one service account is outside CIS 1.7,
# which addresses project-level grants only.
#
# Such a grant is denied to a named individual and permitted to a group. The
# distinction is not bureaucratic. A group is a membership list that access
# review reads and that leaver processes update. A binding to one person is a
# permission that no review will surface, because nobody thinks to look in the
# IAM policy of a service account for it.
deny contains msg if {
  some change in input.resource_changes
  change.type == "google_service_account_iam_member"
  impersonation_roles[change.change.after.role]
  startswith(change.change.after.member, "user:")
  msg := sprintf("[design] iam: %v granted to the individual %v; emergency impersonation is held by a group so that membership is the reviewed control", [change.change.after.role, change.change.after.member])
}

human_principal(member) if startswith(member, "user:")

human_principal(member) if startswith(member, "group:")

