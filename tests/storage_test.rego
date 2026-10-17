package landingzone.storage_test

import data.landingzone.storage
import data.landingzone.testlib as t

compliant_bucket := {"name": "b", "public_access_prevention": "enforced", "uniform_bucket_level_access": true}

test_bucket_granted_to_all_users_is_cis_5_1 if {
	d := storage.deny with input as t.plan([t.create("google_storage_bucket_iam_member", {"bucket": "b", "role": "roles/storage.objectViewer", "member": "allUsers"})])
	t.cites(d, "5.1")
}

test_bucket_binding_to_all_users_is_cis_5_1 if {
	d := storage.deny with input as t.plan([t.create("google_storage_bucket_iam_binding", {"bucket": "b", "role": "roles/storage.objectViewer", "members": ["allUsers"]})])
	t.cites(d, "5.1")
}

test_bucket_without_public_access_prevention_denied if {
	d := storage.deny with input as t.plan([t.create("google_storage_bucket", object.union(compliant_bucket, {"public_access_prevention": "inherited"}))])
	t.has_label(d, "[design] storage")
}

test_bucket_without_uniform_access_is_cis_5_2 if {
	d := storage.deny with input as t.plan([t.create("google_storage_bucket", object.union(compliant_bucket, {"uniform_bucket_level_access": false}))])
	t.cites(d, "5.2")
}

test_compliant_bucket_allowed if {
	d := storage.deny with input as t.plan([t.create("google_storage_bucket", compliant_bucket)])
	count(d) == 0
}

# A data source describing an existing bucket proposes nothing.
test_bucket_data_source_not_judged if {
	d := storage.deny with input as t.plan([t.read("google_storage_bucket", {"name": "b", "uniform_bucket_level_access": false})])
	count(d) == 0
}

test_bucket_deleted_allowed if {
	d := storage.deny with input as t.plan([t.delete("google_storage_bucket")])
	count(d) == 0
}

# 5.1's audit reads the bucket IAM policy. A legacy ACL entry for allUsers is
# also public and is not read here.
test_gap_public_acl_not_detected if {
	d := storage.deny with input as t.plan([t.create("google_storage_bucket_access_control", {"bucket": "b", "entity": "allUsers", "role": "READER"})])
	count(d) == 0
}
