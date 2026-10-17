package landingzone.secrets_test

import data.landingzone.secrets
import data.landingzone.testlib as t

grant(type, role, member) := t.create(type, {"role": role, "member": member})

key := "projects/p/locations/europe-north1/keyRings/core-ring/cryptoKeys/k"

# --- Secrets in configuration (design rules informed by 1.18) ---------------

test_literal_secret_denied if {
	d := secrets.deny with input as t.plan([t.create("google_secret_manager_secret_version", {"secret_data": "s3cret"})])
	t.has_label(d, "[design] secrets")
}

test_withheld_but_known_secret_denied if {
	d := secrets.deny with input as t.plan([t.create_unknown("google_secret_manager_secret_version", {"secret_data": null}, {"secret_data": false})])
	t.has_label(d, "[design] secrets")
}

test_secret_produced_at_apply_time_allowed if {
	d := secrets.deny with input as t.plan([t.create_unknown("google_secret_manager_secret_version", {}, {"secret_data": true})])
	count(d) == 0
}

# --- CIS 1.11: key rotation within 90 days ----------------------------------

test_key_without_rotation_is_cis_1_11 if {
	d := secrets.deny with input as t.plan([t.create("google_kms_crypto_key", {"name": "k", "rotation_period": null})])
	t.cites(d, "1.11")
}

test_rotation_of_exactly_90_days_allowed if {
	d := secrets.deny with input as t.plan([t.create("google_kms_crypto_key", {"name": "k", "rotation_period": "7776000s"})])
	count(d) == 0
}

test_rotation_one_second_over_90_days_is_cis_1_11 if {
	d := secrets.deny with input as t.plan([t.create("google_kms_crypto_key", {"name": "k", "rotation_period": "7776001s"})])
	t.cites(d, "1.11")
}

test_key_deleted_allowed if {
	d := secrets.deny with input as t.plan([t.delete("google_kms_crypto_key")])
	count(d) == 0
}

# --- Customer-managed key on data buckets (design rule) ---------------------

test_bucket_without_cmek_denied if {
	d := secrets.deny with input as t.plan([t.create("google_storage_bucket", {"name": "b", "encryption": []})])
	t.has_label(d, "[design] secrets")
}

test_bucket_with_cmek_allowed if {
	d := secrets.deny with input as t.plan([t.create("google_storage_bucket", {"name": "b", "encryption": [{"default_kms_key_name": key}]})])
	count(d) == 0
}

# --- CIS 1.12: KMS Admin is not combined with encrypt or decrypt ------------

test_kms_admin_and_encrypter_decrypter_is_cis_1_12 if {
	d := secrets.deny with input as t.plan([
		grant("google_project_iam_member", "roles/cloudkms.admin", t.user),
		grant("google_kms_crypto_key_iam_member", "roles/cloudkms.cryptoKeyEncrypterDecrypter", t.user),
	])
	t.cites(d, "1.12")
}

test_kms_admin_on_key_ring_and_encrypter_is_cis_1_12 if {
	d := secrets.deny with input as t.plan([
		grant("google_kms_key_ring_iam_member", "roles/cloudkms.admin", t.user),
		grant("google_kms_crypto_key_iam_member", "roles/cloudkms.cryptoKeyEncrypter", t.user),
	])
	t.cites(d, "1.12")
}

test_kms_admin_and_decrypter_through_binding_is_cis_1_12 if {
	d := secrets.deny with input as t.plan([
		t.create("google_project_iam_binding", {"role": "roles/cloudkms.admin", "members": [t.user]}),
		t.create("google_kms_crypto_key_iam_binding", {"role": "roles/cloudkms.cryptoKeyDecrypter", "members": [t.user]}),
	])
	t.cites(d, "1.12")
}

test_kms_admin_alone_allowed if {
	d := secrets.deny with input as t.plan([grant("google_project_iam_member", "roles/cloudkms.admin", t.user)])
	count(d) == 0
}

test_kms_admin_and_decrypter_held_by_different_people_allowed if {
	d := secrets.deny with input as t.plan([
		grant("google_project_iam_member", "roles/cloudkms.admin", t.user),
		grant("google_kms_crypto_key_iam_member", "roles/cloudkms.cryptoKeyDecrypter", "user:other@example.com"),
	])
	count(d) == 0
}

# The rule sees one plan. A pair split across two changes is two inputs, and
# neither contains the violation.
test_gap_kms_separation_split_across_plans_not_detected if {
	a := secrets.deny with input as t.plan([grant("google_project_iam_member", "roles/cloudkms.admin", t.user)])
	b := secrets.deny with input as t.plan([grant("google_kms_crypto_key_iam_member", "roles/cloudkms.cryptoKeyEncrypterDecrypter", t.user)])
	t.cites_none(a, "1.12")
	t.cites_none(b, "1.12")
}

# --- Object read together with decrypt (design rule informed by 1.12) -------

test_object_reader_with_decrypt_denied if {
	d := secrets.deny with input as t.plan([
		grant("google_storage_bucket_iam_member", "roles/storage.objectViewer", t.sa),
		grant("google_kms_crypto_key_iam_member", "roles/cloudkms.cryptoKeyEncrypterDecrypter", t.sa),
	])
	t.has_label(d, "[design] secrets")
}

# objectCreator can write objects but not read them, so it is not the pattern.
test_object_creator_with_decrypt_allowed if {
	d := secrets.deny with input as t.plan([
		grant("google_storage_bucket_iam_member", "roles/storage.objectCreator", t.sa),
		grant("google_kms_crypto_key_iam_member", "roles/cloudkms.cryptoKeyDecrypter", t.sa),
	])
	count(d) == 0
}

# --- CIS 1.10: keys not public ----------------------------------------------

test_key_granted_to_all_users_is_cis_1_10 if {
	d := secrets.deny with input as t.plan([grant("google_kms_crypto_key_iam_member", "roles/cloudkms.viewer", "allUsers")])
	t.cites(d, "1.10")
}

test_key_ring_granted_to_all_authenticated_users_is_cis_1_10 if {
	d := secrets.deny with input as t.plan([grant("google_kms_key_ring_iam_member", "roles/cloudkms.viewer", "allAuthenticatedUsers")])
	t.cites(d, "1.10")
}
