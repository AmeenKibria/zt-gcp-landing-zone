package landingzone.iam

import data.landingzone.lib

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
# CIS GCP Foundation Benchmark v5.0.0: 1.6, 1.7.

hierarchy_levels := {"organization", "folder", "project"}

basic_admin_roles := {"roles/owner", "roles/editor"}

impersonation_roles := {
  "roles/iam.serviceAccountTokenCreator",
  "roles/iam.serviceAccountUser",
}

# CIS 1.6 - "Ensure That Service Account Has No Admin Privileges". The audit looks
# for user-managed service accounts holding Owner, Editor, or any role whose name
# contains "admin" or "Admin". The audit reads the project policy; a grant at a
# folder or the organisation reaches further, so those levels are read as well.
#
# An earlier version cited 1.6 for Owner or Editor granted to anyone, a person
# included, while a service account holding roles/compute.admin was refused under
# a design label. Both were the wrong way round: the benchmark addresses service
# accounts, and its role test is wider than the two basic roles.
cis_1_6_role(role) if basic_admin_roles[role]

cis_1_6_role(role) if contains(lower(role), "admin")

deny contains msg if {
  some grant in lib.grants
  hierarchy_levels[grant.level]
  lib.user_managed_service_account(grant.member)
  cis_1_6_role(grant.role)
  msg := sprintf("[CIS 1.6] iam: %v holds %v at %v level; a service account must not hold an admin, owner or editor role", [grant.member, grant.role, grant.level])
}

# Beyond the benchmark. Owner and Editor granted to anyone who is not a
# user-managed service account: people, groups, domains and Google-managed
# accounts. The benchmark does not state this; least privilege does.
deny contains msg if {
  some grant in lib.grants
  hierarchy_levels[grant.level]
  basic_admin_roles[grant.role]
  not lib.user_managed_service_account(grant.member)
  msg := sprintf("[design] iam: basic role %v granted to %v at %v level; use a predefined or custom role", [grant.role, grant.member, grant.level])
}

# Beyond the benchmark. roles/viewer confers no admin privilege, so CIS 1.6 does
# not reach it. Its scope is nonetheless unbounded, and it widens on its own as
# Google adds services to the platform, so a principal granted it today holds
# read access to resource types that did not exist when the grant was reviewed.
# This landing zone grants roles/browser plus bounded predefined roles instead.
deny contains msg if {
  some grant in lib.grants
  hierarchy_levels[grant.level]
  grant.role == "roles/viewer"
  msg := sprintf("[design] iam: roles/viewer granted to %v; its scope is unbounded, use roles/browser or a bounded predefined role", [grant.member])
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
  some grant in lib.grants
  grant.level == "project"
  impersonation_roles[grant.role]
  human_principal(grant.member)
  msg := sprintf("[CIS 1.7] iam: %v granted at project level to %v; it confers impersonation over every service account in the project", [grant.role, grant.member])
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
  some grant in lib.grants
  grant.level == "service_account"
  impersonation_roles[grant.role]
  startswith(grant.member, "user:")
  msg := sprintf("[design] iam: %v granted to the individual %v; emergency impersonation is held by a group so that membership is the reviewed control", [grant.role, grant.member])
}

human_principal(member) if startswith(member, "user:")

human_principal(member) if startswith(member, "group:")
