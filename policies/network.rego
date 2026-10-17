package landingzone.network

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

# Zero Trust tenets 2 and 4 (Rose et al., 2020, pp. 6-7). Micro-segmentation is
# one of the three minimum controls identified by Ajani (2024).
# CIS GCP Foundation Benchmark v5.0.0: 3.6, 3.7, 3.10.

# FIREWALL EXPOSURE
#
# The benchmark's audit for 3.6 and 3.7 counts an ingress rule as open when the
# source is 0.0.0.0/0, the protocol is tcp or all, and the ports are the port
# itself, a range containing it, or not set at all; an unset port list means
# every port. An earlier version matched only an explicitly listed port, so a
# range or an empty list opened SSH without a denial, and it refused UDP 22,
# which the benchmark does not count.

ingress(after) if object.get(after, "direction", null) == null

ingress(after) if after.direction == "INGRESS"

from_world(after) if {
  some range in object.get(after, "source_ranges", [])
  range == "0.0.0.0/0"
}

carries_tcp(rule) if lower(rule.protocol) in {"tcp", "all", "6"}

ports_cover(rule, _) if object.get(rule, "ports", null) == null

ports_cover(rule, _) if count(rule.ports) == 0

ports_cover(rule, port) if {
  some p in rule.ports
  p == sprintf("%d", [port])
}

ports_cover(rule, port) if {
  some p in rule.ports
  bounds := split(p, "-")
  count(bounds) == 2
  to_number(bounds[0]) <= port
  port <= to_number(bounds[1])
}

exposes(change, port) if {
  change.type == "google_compute_firewall"
  ingress(change.change.after)
  from_world(change.change.after)
  some rule in object.get(change.change.after, "allow", [])
  carries_tcp(rule)
  ports_cover(rule, port)
}

# CIS 3.6 - SSH restricted from the internet.
deny contains msg if {
  some change in lib.proposed
  exposes(change, 22)
  msg := sprintf("[CIS 3.6] network: firewall %v exposes port 22 to 0.0.0.0/0", [change.change.after.name])
}

# CIS 3.7 - RDP restricted from the internet.
deny contains msg if {
  some change in lib.proposed
  exposes(change, 3389)
  msg := sprintf("[CIS 3.7] network: firewall %v exposes port 3389 to 0.0.0.0/0", [change.change.after.name])
}

# Beyond the benchmark. Database ports opened to the internet. An earlier version
# folded these into the 3.6/3.7 label, which named a recommendation that does not
# mention them.
database_ports := {3306, 5432}

deny contains msg if {
  some change in lib.proposed
  some port in database_ports
  exposes(change, port)
  msg := sprintf("[design] network: firewall %v exposes database port %v to 0.0.0.0/0; databases are reached over private connectivity", [change.change.after.name, port])
}

# FLOW LOGS
#
# CIS 3.10 - flow logs on every subnet, configured so that all traffic is logged:
# a 5-second aggregation interval, 100% sampling, all metadata, and no filter.
# An earlier version checked only that a log_config block existed, so a subnet
# sampling half its flows passed. Subnets reserved for proxy load balancers
# cannot carry flow logs, as the benchmark notes, and are not judged.
#
# This is an attribute check on a subnet that is in the plan, not an absence
# check across the estate. A subnet the plan does not mention is not seen.

proxy_purposes := {"REGIONAL_MANAGED_PROXY", "GLOBAL_MANAGED_PROXY", "INTERNAL_HTTPS_LOAD_BALANCER"}

judged_subnet(change) if {
  change.type == "google_compute_subnetwork"
  not proxy_purposes[object.get(change.change.after, "purpose", "")]
}

log_configs(change) := configs if {
  configs := object.get(change.change.after, "log_config", [])
  is_array(configs)
} else := []

deny contains msg if {
  some change in lib.proposed
  judged_subnet(change)
  count(log_configs(change)) == 0
  msg := sprintf("[CIS 3.10] network: subnet %v has no flow log configuration; nothing that crosses it will be recorded", [change.change.after.name])
}

flow_log_settings := {"aggregation_interval", "flow_sampling", "metadata", "filter_expr"}

off_benchmark(cfg, "aggregation_interval") if object.get(cfg, "aggregation_interval", "") != "INTERVAL_5_SEC"

off_benchmark(cfg, "flow_sampling") if object.get(cfg, "flow_sampling", 0) != 1

off_benchmark(cfg, "metadata") if object.get(cfg, "metadata", "") != "INCLUDE_ALL_METADATA"

off_benchmark(cfg, "filter_expr") if not object.get(cfg, "filter_expr", "true") in {"true", "", null}

deny contains msg if {
  some change in lib.proposed
  judged_subnet(change)
  some cfg in log_configs(change)
  deviations := {setting | some setting in flow_log_settings; off_benchmark(cfg, setting)}
  count(deviations) > 0
  msg := sprintf("[CIS 3.10] network: subnet %v flow logs do not meet the benchmark settings (%v)", [change.change.after.name, concat(", ", sort(deviations))])
}
