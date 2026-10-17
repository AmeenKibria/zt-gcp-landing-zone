package landingzone.iam_test

import data.landingzone.iam
import data.landingzone.testlib as t

grant(type, role, member) := t.create(type, {"role": role, "member": member})

# --- CIS 1.6: service accounts hold no admin, owner or editor role ----------
# The benchmark's audit looks for user-managed service accounts holding a role
# that contains "admin" or "Admin", or that is Editor or Owner.

test_owner_to_service_account_is_cis_1_6 if {
	d := iam.deny with input as t.plan([grant("google_project_iam_member", "roles/owner", t.sa)])
	t.cites(d, "1.6")
}

test_editor_to_service_account_is_cis_1_6 if {
	d := iam.deny with input as t.plan([grant("google_project_iam_member", "roles/editor", t.sa)])
	t.cites(d, "1.6")
}

test_predefined_admin_role_to_service_account_is_cis_1_6 if {
	d := iam.deny with input as t.plan([grant("google_project_iam_member", "roles/compute.admin", t.sa)])
	t.cites(d, "1.6")
}

test_camel_case_admin_role_to_service_account_is_cis_1_6 if {
	d := iam.deny with input as t.plan([grant("google_project_iam_member", "roles/iam.serviceAccountAdmin", t.sa)])
	t.cites(d, "1.6")
}

test_owner_to_service_account_at_folder_level_is_cis_1_6 if {
	d := iam.deny with input as t.plan([grant("google_folder_iam_member", "roles/owner", t.sa)])
	t.cites(d, "1.6")
}

test_owner_to_service_account_through_binding_is_cis_1_6 if {
	d := iam.deny with input as t.plan([t.create("google_project_iam_binding", {"role": "roles/owner", "members": [t.sa]})])
	t.cites(d, "1.6")
}

# 1.6 is about service accounts. A person granted Owner is refused, but not under
# a label that claims the benchmark says so.
test_owner_to_person_denied_but_not_as_cis_1_6 if {
	d := iam.deny with input as t.plan([grant("google_project_iam_member", "roles/owner", t.user)])
	t.has_label(d, "[design] iam")
	t.cites_none(d, "1.6")
}

test_editor_to_group_denied_as_design if {
	d := iam.deny with input as t.plan([grant("google_project_iam_member", "roles/editor", t.group)])
	t.has_label(d, "[design] iam")
}

test_owner_to_person_through_binding_denied if {
	d := iam.deny with input as t.plan([t.create("google_project_iam_binding", {"role": "roles/owner", "members": [t.user]})])
	t.has_label(d, "[design] iam")
}

test_bounded_role_to_person_allowed if {
	d := iam.deny with input as t.plan([grant("google_project_iam_member", "roles/browser", t.user)])
	count(d) == 0
}

test_viewer_denied_as_design if {
	d := iam.deny with input as t.plan([grant("google_project_iam_member", "roles/viewer", t.user)])
	t.has_label(d, "[design] iam")
}

test_admin_grant_deleted_allowed if {
	d := iam.deny with input as t.plan([t.delete("google_project_iam_member")])
	count(d) == 0
}

# Google-managed service accounts are outside 1.6 by the benchmark's own note.
# A basic role granted to one is still refused, under the design label.
test_google_managed_service_account_editor_denied_as_design if {
	d := iam.deny with input as t.plan([grant("google_project_iam_member", "roles/editor", "serviceAccount:123456789012-compute@developer.gserviceaccount.com")])
	t.has_label(d, "[design] iam")
	t.cites_none(d, "1.6")
}

# --- CIS 1.7: no impersonation roles at project level for users -------------

test_project_token_creator_to_person_is_cis_1_7 if {
	d := iam.deny with input as t.plan([grant("google_project_iam_member", "roles/iam.serviceAccountTokenCreator", t.user)])
	t.cites(d, "1.7")
}

test_project_service_account_user_to_group_is_cis_1_7 if {
	d := iam.deny with input as t.plan([grant("google_project_iam_member", "roles/iam.serviceAccountUser", t.group)])
	t.cites(d, "1.7")
}

test_project_impersonation_through_binding_is_cis_1_7 if {
	d := iam.deny with input as t.plan([t.create("google_project_iam_binding", {"role": "roles/iam.serviceAccountUser", "members": [t.user]})])
	t.cites(d, "1.7")
}

test_project_token_creator_to_service_account_not_cis_1_7 if {
	d := iam.deny with input as t.plan([grant("google_project_iam_member", "roles/iam.serviceAccountTokenCreator", t.sa)])
	t.cites_none(d, "1.7")
}

# --- Impersonation on one service account (design rule) ---------------------

test_service_account_impersonation_to_person_denied if {
	d := iam.deny with input as t.plan([grant("google_service_account_iam_member", "roles/iam.serviceAccountTokenCreator", t.user)])
	t.has_label(d, "[design] iam")
}

test_service_account_impersonation_to_group_allowed if {
	d := iam.deny with input as t.plan([grant("google_service_account_iam_member", "roles/iam.serviceAccountTokenCreator", t.group)])
	count(d) == 0
}
