package landingzone.lib

# Shared readers. This package defines no denials; main.rego collects only `deny`.

# WHAT THE GATE JUDGES
# The gate judges the change it is shown. A managed resource that the plan
# creates, updates or replaces is part of that change. A data source that is only
# read, a resource left as it is, and a resource being deleted are not. Judging
# them would refuse a deletion that removes the problem, or report a condition
# the change does not introduce. Existing state is the posture layer's concern.
proposed contains change if {
	some change in input.resource_changes
	object.get(change, "mode", "managed") == "managed"
	some action in change.change.actions
	action in {"create", "update"}
	is_object(change.change.after)
}

# IAM GRANTS, NORMALISED
# A *_iam_member resource grants one role to one member. A *_iam_binding grants
# one role to a list of members. Both are read, so a binding cannot be used to
# step round a rule written for members. Authoritative *_iam_policy resources
# carry the policy as an encoded string and are not read; that is a stated gap.
iam_level := {
	"google_organization_iam_member": "organization",
	"google_organization_iam_binding": "organization",
	"google_folder_iam_member": "folder",
	"google_folder_iam_binding": "folder",
	"google_project_iam_member": "project",
	"google_project_iam_binding": "project",
	"google_service_account_iam_member": "service_account",
	"google_service_account_iam_binding": "service_account",
	"google_storage_bucket_iam_member": "bucket",
	"google_storage_bucket_iam_binding": "bucket",
	"google_kms_key_ring_iam_member": "key_ring",
	"google_kms_key_ring_iam_binding": "key_ring",
	"google_kms_crypto_key_iam_member": "crypto_key",
	"google_kms_crypto_key_iam_binding": "crypto_key",
}

grants contains grant if {
	some change in proposed
	level := iam_level[change.type]
	member := change.change.after.member
	grant := {"level": level, "role": change.change.after.role, "member": member, "address": change.address, "after": change.change.after}
}

grants contains grant if {
	some change in proposed
	level := iam_level[change.type]
	members := object.get(change.change.after, "members", [])
	is_array(members)
	some member in members
	grant := {"level": level, "role": change.change.after.role, "member": member, "address": change.address, "after": change.change.after}
}

# A user-managed service account, the kind the benchmark's IAM audits address.
# Google-managed accounts share the domain suffix only for some services; the
# benchmark tells the reader to exclude those by name, which a plan cannot do
# reliably, so the suffix is the test.
user_managed_service_account(member) if {
	startswith(member, "serviceAccount:")
	endswith(member, ".iam.gserviceaccount.com")
}

public_principals := {"allUsers", "allAuthenticatedUsers"}
