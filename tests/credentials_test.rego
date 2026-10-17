package landingzone.credentials_test

import data.landingzone.credentials
import data.landingzone.testlib as t

pool := "projects/123456789012/locations/global/workloadIdentityPools/github-pool"

# --- CIS 1.5: user-managed service account keys -----------------------------

test_key_creation_denied if {
	d := credentials.deny with input as t.plan([t.create("google_service_account_key", {"private_key_type": "TYPE_GOOGLE_CREDENTIALS_FILE"})])
	t.cites(d, "1.5")
}

# Deleting a key is the remediation 1.5 asks for. It must not be refused.
test_key_deletion_allowed if {
	d := credentials.deny with input as t.plan([t.delete("google_service_account_key")])
	count(d) == 0
}

# A data source that reads an existing key proposes nothing.
test_key_data_source_allowed if {
	d := credentials.deny with input as t.plan([t.read("google_service_account_key", {"name": "k"})])
	count(d) == 0
}

test_constraint_switched_off_legacy_name_denied if {
	d := credentials.deny with input as t.plan([t.create("google_org_policy_policy", {
		"name": "projects/p/policies/iam.disableServiceAccountKeyCreation",
		"spec": [{"rules": [{"enforce": "FALSE"}]}],
	})])
	t.cites(d, "1.5")
}

test_constraint_switched_off_managed_name_denied if {
	d := credentials.deny with input as t.plan([t.create("google_org_policy_policy", {
		"name": "organizations/1/policies/iam.managed.disableServiceAccountKeyCreation",
		"spec": [{"rules": [{"enforce": "FALSE"}]}],
	})])
	t.cites(d, "1.5")
}

test_constraint_enforced_allowed if {
	d := credentials.deny with input as t.plan([t.create("google_org_policy_policy", {
		"name": "projects/p/policies/iam.disableServiceAccountKeyCreation",
		"spec": [{"rules": [{"enforce": "TRUE"}]}],
	})])
	count(d) == 0
}

# --- Federation scoping (design rules) --------------------------------------

test_provider_without_condition_denied if {
	d := credentials.deny with input as t.plan([t.create("google_iam_workload_identity_pool_provider", {"workload_identity_pool_provider_id": "p"})])
	t.has_label(d, "[design] credentials")
}

test_provider_with_empty_condition_denied if {
	d := credentials.deny with input as t.plan([t.create("google_iam_workload_identity_pool_provider", {"attribute_condition": ""})])
	t.has_label(d, "[design] credentials")
}

test_provider_with_condition_allowed if {
	d := credentials.deny with input as t.plan([t.create("google_iam_workload_identity_pool_provider", {"attribute_condition": "assertion.repository == \"owner/repo\""})])
	count(d) == 0
}

test_pool_wide_principal_set_denied if {
	d := credentials.deny with input as t.plan([t.create("google_service_account_iam_member", {
		"role": "roles/iam.workloadIdentityUser",
		"member": concat("", ["principalSet://iam.googleapis.com/", pool, "/*"]),
	})])
	t.has_label(d, "[design] credentials")
}

test_repository_scoped_principal_set_allowed if {
	d := credentials.deny with input as t.plan([t.create("google_service_account_iam_member", {
		"role": "roles/iam.workloadIdentityUser",
		"member": concat("", ["principalSet://iam.googleapis.com/", pool, "/attribute.repository/owner/repo"]),
	})])
	count(d) == 0
}

test_member_unknown_at_plan_time_denied if {
	d := credentials.deny with input as t.plan([t.create_unknown(
		"google_service_account_iam_member",
		{"role": "roles/iam.workloadIdentityUser"},
		{"member": true},
	)])
	t.has_label(d, "[design] credentials")
}

# A binding grants the same role to a list of members. It must not be a way round
# a rule written for single members.
test_pool_wide_principal_set_in_binding_denied if {
	d := credentials.deny with input as t.plan([t.create("google_service_account_iam_binding", {
		"role": "roles/iam.workloadIdentityUser",
		"members": [concat("", ["principalSet://iam.googleapis.com/", pool, "/*"])],
	})])
	t.has_label(d, "[design] credentials")
}

test_binding_members_unknown_at_plan_time_denied if {
	d := credentials.deny with input as t.plan([t.create_unknown(
		"google_service_account_iam_binding",
		{"role": "roles/iam.workloadIdentityUser"},
		{"members": true},
	)])
	t.has_label(d, "[design] credentials")
}
