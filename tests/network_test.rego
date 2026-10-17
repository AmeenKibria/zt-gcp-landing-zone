package landingzone.network_test

import data.landingzone.network
import data.landingzone.testlib as t

firewall(allow, ranges) := t.create("google_compute_firewall", {"name": "fw", "direction": "INGRESS", "allow": allow, "source_ranges": ranges})

world := ["0.0.0.0/0"]

# --- CIS 3.6 and 3.7: SSH and RDP not open to the internet ------------------
# The benchmark's audit counts a rule as open when the protocol is tcp or all and
# the ports are 22 (or 3389), a range containing it, or not set at all.

test_ssh_explicit_port_is_cis_3_6 if {
	d := network.deny with input as t.plan([firewall([{"protocol": "tcp", "ports": ["22"]}], world)])
	t.cites(d, "3.6")
}

test_rdp_explicit_port_is_cis_3_7 if {
	d := network.deny with input as t.plan([firewall([{"protocol": "tcp", "ports": ["3389"]}], world)])
	t.cites(d, "3.7")
}

test_ssh_inside_port_range_is_cis_3_6 if {
	d := network.deny with input as t.plan([firewall([{"protocol": "tcp", "ports": ["20-30"]}], world)])
	t.cites(d, "3.6")
}

test_all_tcp_ports_is_cis_3_6_and_3_7 if {
	d := network.deny with input as t.plan([firewall([{"protocol": "tcp", "ports": []}], world)])
	t.cites(d, "3.6")
	t.cites(d, "3.7")
}

test_all_protocols_is_cis_3_6 if {
	d := network.deny with input as t.plan([firewall([{"protocol": "all"}], world)])
	t.cites(d, "3.6")
}

test_ssh_from_iap_range_allowed if {
	d := network.deny with input as t.plan([firewall([{"protocol": "tcp", "ports": ["22"]}], ["35.235.240.0/20"])])
	count(d) == 0
}

test_udp_port_22_allowed if {
	d := network.deny with input as t.plan([firewall([{"protocol": "udp", "ports": ["22"]}], world)])
	count(d) == 0
}

test_egress_rule_not_judged if {
	d := network.deny with input as t.plan([t.create("google_compute_firewall", {
		"name": "fw", "direction": "EGRESS",
		"allow": [{"protocol": "tcp", "ports": ["22"]}],
		"destination_ranges": world,
	})])
	count(d) == 0
}

test_firewall_deleted_allowed if {
	d := network.deny with input as t.plan([t.delete("google_compute_firewall")])
	count(d) == 0
}

# Database ports are refused too, but 3.6 and 3.7 do not name them.
test_database_port_denied_as_design_not_cis if {
	d := network.deny with input as t.plan([firewall([{"protocol": "tcp", "ports": ["5432"]}], world)])
	t.has_label(d, "[design] network")
	t.cites_none(d, "3.6")
	t.cites_none(d, "3.7")
}

# The benchmark's audit names 0.0.0.0/0. An IPv6 world range is not read.
test_gap_ipv6_world_range_not_detected if {
	d := network.deny with input as t.plan([firewall([{"protocol": "tcp", "ports": ["22"]}], ["::/0"])])
	count(d) == 0
}

# --- CIS 3.10: flow logs on every subnet, with the benchmark's settings -----

subnet(after) := t.create("google_compute_subnetwork", object.union({"name": "s"}, after))

cis_log := {"aggregation_interval": "INTERVAL_5_SEC", "flow_sampling": 1, "metadata": "INCLUDE_ALL_METADATA", "filter_expr": "true"}

test_subnet_without_flow_logs_is_cis_3_10 if {
	d := network.deny with input as t.plan([subnet({})])
	t.cites(d, "3.10")
}

test_subnet_with_default_sampling_is_cis_3_10 if {
	d := network.deny with input as t.plan([subnet({"log_config": [object.union(cis_log, {"flow_sampling": 0.5})]})])
	t.cites(d, "3.10")
}

test_subnet_with_long_interval_is_cis_3_10 if {
	d := network.deny with input as t.plan([subnet({"log_config": [object.union(cis_log, {"aggregation_interval": "INTERVAL_10_MIN"})]})])
	t.cites(d, "3.10")
}

test_subnet_with_filtered_logs_is_cis_3_10 if {
	d := network.deny with input as t.plan([subnet({"log_config": [object.union(cis_log, {"filter_expr": "inIpRange(connection.src_ip, '10.0.0.0/8')"})]})])
	t.cites(d, "3.10")
}

test_subnet_with_cis_settings_allowed if {
	d := network.deny with input as t.plan([subnet({"log_config": [cis_log]})])
	count(d) == 0
}

# The benchmark notes that subnets reserved for proxy load balancers cannot
# carry flow logs.
test_proxy_only_subnet_not_judged if {
	d := network.deny with input as t.plan([subnet({"purpose": "REGIONAL_MANAGED_PROXY"})])
	count(d) == 0
}

# The provider defaults direction to INGRESS. A rule that omits it is ingress.
test_firewall_without_direction_is_judged_as_ingress if {
	d := network.deny with input as t.plan([t.create("google_compute_firewall", {"name": "fw", "allow": [{"protocol": "tcp", "ports": ["22"]}], "source_ranges": world})])
	t.cites(d, "3.6")
}

test_subnet_with_null_log_config_is_cis_3_10 if {
	d := network.deny with input as t.plan([subnet({"log_config": null})])
	t.cites(d, "3.10")
}

test_subnet_without_metadata_is_cis_3_10 if {
	d := network.deny with input as t.plan([subnet({"log_config": [object.union(cis_log, {"metadata": "EXCLUDE_ALL_METADATA"})]})])
	t.cites(d, "3.10")
}
