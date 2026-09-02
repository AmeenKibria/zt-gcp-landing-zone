package landingzone.credentials

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

# Zero Trust tenet 6: authentication and authorisation dynamic and strictly
# enforced (Rose et al., 2020, pp. 6-7). A static exported key is neither.
# CIS GCP Foundation Benchmark v5.0.0: 1.5, 1.8.

# CIS 1.5 - only GCP-managed service account keys should exist.
deny contains msg if {
  some change in input.resource_changes
  change.type == "google_service_account_key"
  # service_account_id references another resource, so it is unknown at plan
  # time. The address identifies the offending resource without it.
  msg := sprintf("[CIS 1.5] credentials: %v creates a user-managed service account key; use identity federation", [change.address])
}

# Do not let the guardrail itself be switched off.
deny contains msg if {
  some change in input.resource_changes
  change.type == "google_org_policy_policy"
  # Google publishes two generations of constraint identifier for the same
  # control: the legacy "iam.disableServiceAccountKeyCreation" and the newer
  # managed "iam.managed.disableServiceAccountKeyCreation". Matching the full
  # legacy string would miss the managed one entirely, so only the distinctive
  # suffix is matched. A rule that hard-codes a vendor identifier inherits the
  # vendor's renaming schedule.
  contains(change.change.after.name, "disableServiceAccountKeyCreation")
  some rule in change.change.after.spec.rules
  rule.enforce == "FALSE"
  msg := "[CIS 1.5] credentials: constraint iam.disableServiceAccountKeyCreation is being turned off"
}

# FEDERATION SCOPING
#
# Replacing a downloaded key with federation removes a stored secret. It does
# not by itself remove a long-lived path in. Federation that accepts any caller
# the issuer will sign for is a worse credential than the key it replaced,
# because nothing has to leak for it to be used.
#
# The benchmark does not reach this. CIS 1.5 and 1.8 address service account
# keys, which is the mechanism federation exists to avoid, so these are design
# rules of this landing zone rather than CIS requirements.

no_attribute_condition(after) if object.get(after, "attribute_condition", null) == null

no_attribute_condition(after) if object.get(after, "attribute_condition", null) == ""

deny contains msg if {
  some change in input.resource_changes
  change.type == "google_iam_workload_identity_pool_provider"
  no_attribute_condition(change.change.after)
  msg := sprintf("[design] credentials: %v sets no attribute_condition; every identity the issuer signs for can exchange a token here", [change.address])
}

# The scope of this binding is carried in the member string, and the member
# string is not always knowable when the plan is made.
#
# A principalSet that interpolates the name of a pool created in the same plan
# depends on the project number, which is a server-side value. Terraform does
# not guess it. It omits `member` from `after` altogether and records
# member: true under `after_unknown`. A rule that reads the value therefore
# matches nothing and says nothing, and it says nothing about the single most
# dangerous misconfiguration in the chain.
#
# Both cases are handled below, and they are mutually exclusive. A known member
# is checked. An unknown member is denied on its own terms, because a scope that
# cannot be verified here has not been verified anywhere.

deny contains msg if {
  some change in input.resource_changes
  change.type == "google_service_account_iam_member"
  change.change.after.role == "roles/iam.workloadIdentityUser"
  member := object.get(change.change.after, "member", "")
  endswith(member, "/*")
  msg := sprintf("[design] credentials: %v grants impersonation to an entire identity pool; scope the principalSet to one repository", [member])
}

deny contains msg if {
  some change in input.resource_changes
  change.type == "google_service_account_iam_member"
  change.change.after.role == "roles/iam.workloadIdentityUser"
  object.get(change.change, ["after_unknown", "member"], false) == true
  msg := sprintf("[design] credentials: %v grants workloadIdentityUser to a principalSet that is not known at plan time; its scope cannot be verified here", [change.address])
}
