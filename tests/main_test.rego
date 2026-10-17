package landingzone.main_test

import data.main
import data.landingzone.testlib as t

# The aggregator returns every package's denials as one set of strings.
test_aggregator_collects_across_packages if {
	d := main.deny with input as t.plan([
		t.create("google_service_account_key", {}),
		t.create("google_storage_bucket_iam_member", {"bucket": "b", "role": "roles/storage.objectViewer", "member": "allUsers"}),
	])
	t.cites(d, "1.5")
	t.cites(d, "5.1")
}

test_empty_plan_has_no_denials if {
	d := main.deny with input as t.plan([])
	count(d) == 0
}
