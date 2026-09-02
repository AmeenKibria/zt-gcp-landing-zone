package landingzone.logging

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
  msg := sprintf("ts-05 [CIS 2.1]: audit config for allServices is missing log types %v", [missing])
}

# No principal may be exempted from audit logging.
deny contains msg if {
  some change in input.resource_changes
  change.type == "google_project_iam_audit_config"
  some cfg in change.change.after.audit_log_config
  count(cfg.exempted_members) > 0
  msg := sprintf("ts-05 [CIS 2.1]: %v exempted from %v logging on %v", [cfg.exempted_members, cfg.log_type, change.change.after.service])
}
