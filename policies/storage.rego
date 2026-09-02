package landingzone.storage

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

# Zero Trust tenet 2: all communication secured regardless of network location
# (Rose et al., 2020, pp. 6-7).
# CIS GCP Foundation Benchmark v5.0.0: 5.1, 5.2.

public_principals := {"allUsers", "allAuthenticatedUsers"}

# An optional attribute the configuration omits arrives as null, not as an
# absent key, and Rego treats null as truthy. Absence is therefore tested with
# object.get and an explicit comparison, never with a bare `not`.

# CIS 5.1 - buckets must not be anonymously or publicly accessible. The
# benchmark's audit for 5.1 inspects the bucket IAM policy for allUsers and
# allAuthenticatedUsers, so only the first rule below implements it. Public
# access prevention is a separate mechanism that the benchmark does not state,
# and its rule is labelled accordingly.
deny contains msg if {
  some change in input.resource_changes
  change.type == "google_storage_bucket_iam_member"
  public_principals[change.change.after.member]
  msg := sprintf("[CIS 5.1] storage: bucket %v grants %v to %v", [change.change.after.bucket, change.change.after.role, change.change.after.member])
}

deny contains msg if {
  some change in input.resource_changes
  change.type == "google_storage_bucket"
  object.get(change.change.after, "public_access_prevention", "") != "enforced"
  msg := sprintf("[design] storage: bucket %v does not set public_access_prevention = enforced", [change.change.after.name])
}

# CIS 5.2 - uniform bucket-level access must be enabled.
deny contains msg if {
  some change in input.resource_changes
  change.type == "google_storage_bucket"
  object.get(change.change.after, "uniform_bucket_level_access", false) != true
  msg := sprintf("[CIS 5.2] storage: bucket %v does not enable uniform_bucket_level_access", [change.change.after.name])
}
