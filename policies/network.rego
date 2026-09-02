package landingzone.network

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

# Zero Trust tenets 2 and 4 (Rose et al., 2020, pp. 6-7). Micro-segmentation is
# one of the three minimum controls identified by Ajani (2024).
# CIS GCP Foundation Benchmark v5.0.0: 3.6, 3.7.

admin_ports := {"22", "3389", "3306", "5432"}

# CIS 3.6 and 3.7 - SSH and RDP must be restricted from the internet.
deny contains msg if {
  some change in input.resource_changes
  change.type == "google_compute_firewall"
  some range in change.change.after.source_ranges
  range == "0.0.0.0/0"
  some rule in change.change.after.allow
  some port in rule.ports
  admin_ports[port]
  msg := sprintf("[CIS 3.6/3.7] network: firewall %v exposes port %v to 0.0.0.0/0", [change.change.after.name, port])
}

# Containment: a workload identity should not hold admin rights in another project.
deny contains msg if {
  some change in input.resource_changes
  change.type == "google_project_iam_member"
  startswith(change.change.after.member, "serviceAccount:")
  endswith(change.change.after.role, ".admin")
  msg := sprintf("[design] network: %v holds %v, enabling movement beyond its own workload", [change.change.after.member, change.change.after.role])
}
