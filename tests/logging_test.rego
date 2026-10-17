package landingzone.logging_test

import data.landingzone.logging
import data.landingzone.testlib as t

audit(type, service, configs) := t.create(type, {"service": service, "audit_log_config": configs})

all_types := [{"log_type": "ADMIN_READ"}, {"log_type": "DATA_READ"}, {"log_type": "DATA_WRITE"}]

test_missing_data_log_types_is_cis_2_1 if {
	d := logging.deny with input as t.plan([audit("google_project_iam_audit_config", "allServices", [{"log_type": "ADMIN_READ"}])])
	t.cites(d, "2.1")
}

test_all_log_types_allowed if {
	d := logging.deny with input as t.plan([audit("google_project_iam_audit_config", "allServices", all_types)])
	count(d) == 0
}

test_exempted_member_is_cis_2_1 if {
	d := logging.deny with input as t.plan([audit("google_project_iam_audit_config", "storage.googleapis.com", [{"log_type": "DATA_READ", "exempted_members": [t.sa]}])])
	t.cites(d, "2.1")
}

test_null_exemptions_allowed if {
	d := logging.deny with input as t.plan([audit("google_project_iam_audit_config", "allServices", [
		{"log_type": "ADMIN_READ", "exempted_members": null},
		{"log_type": "DATA_READ", "exempted_members": null},
		{"log_type": "DATA_WRITE", "exempted_members": null},
	])])
	count(d) == 0
}

# The benchmark audits organisation, folder and project. A folder-level config
# that narrows the log types is the same failure one level up.
test_folder_level_missing_types_is_cis_2_1 if {
	d := logging.deny with input as t.plan([audit("google_folder_iam_audit_config", "allServices", [{"log_type": "ADMIN_READ"}])])
	t.cites(d, "2.1")
}

test_service_specific_config_not_judged_for_types if {
	d := logging.deny with input as t.plan([audit("google_project_iam_audit_config", "storage.googleapis.com", [{"log_type": "DATA_READ"}])])
	count(d) == 0
}

# A plan that never mentions audit configuration is indistinguishable from one
# whose configuration is correct. Absence cannot be decided from one plan.
test_gap_absent_audit_config_not_detected if {
	d := logging.deny with input as t.plan([])
	count(d) == 0
}
