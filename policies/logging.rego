package landingzone.logging

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

# Zero Trust tenets 5 and 7 (Rose et al., 2020, pp. 6-7). Ineffective monitoring
# was one of five control failures in the Capital One breach
# (Khan et al., 2022, Section 3.2).
# CIS GCP Foundation Benchmark v5.0.0: 2.1, 2.6.

required_log_types := {"ADMIN_READ", "DATA_READ", "DATA_WRITE"}

configured_types(change) := {t |
  some cfg in change.change.after.audit_log_config
  t := cfg.log_type
}

# CIS 2.1 - cloud audit logging must be configured properly.
deny contains msg if {
  some change in input.resource_changes
  change.type == "google_project_iam_audit_config"
  change.change.after.service == "allServices"
  missing := required_log_types - configured_types(change)
  count(missing) > 0
  msg := sprintf("[CIS 2.1] logging: audit config for allServices is missing log types %v", [missing])
}

# No principal may be exempted from audit logging.
deny contains msg if {
  some change in input.resource_changes
  change.type == "google_project_iam_audit_config"
  some cfg in change.change.after.audit_log_config
  count(cfg.exempted_members) > 0
  msg := sprintf("[CIS 2.1] logging: %v exempted from %v logging on %v", [cfg.exempted_members, cfg.log_type, change.change.after.service])
}
