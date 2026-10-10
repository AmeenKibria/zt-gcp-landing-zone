package landingzone.secrets

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

# Zero Trust tenets 3 and 6 (Rose et al., 2020, pp. 6-7).
# CIS GCP Foundation Benchmark v5.0.0: 1.10, 1.11, 1.12. See the note on 1.18 below.
#
# Two separation rules follow. The first implements CIS 1.12 as the benchmark
# states it: no principal holds Cloud KMS Admin together with a role that
# encrypts or decrypts with a key. The second encodes a documented failure that
# 1.12 does not state: at Capital One the data was encrypted, but the
# compromised role also held decrypt, so encryption provided no protection
# (Khan et al., 2022, Section 3.2). That one is labelled [design].
#
# NOTE ON UNSET ATTRIBUTES
# An optional attribute that the configuration omits is not absent from the
# plan. It is present with the value null, and an omitted block is present as
# an empty array. Rego treats both as truthy, so `not after.x` never matches
# for them. Every absence test below therefore reads the value explicitly with
# object.get and compares it.

max_rotation_seconds := 7776000        # 90 days

# Beyond the benchmark. CIS 1.18 is the nearest statement of this principle,
# but it is Manual and it addresses secrets in Cloud Functions environment
# variables specifically. It cannot anchor an automated rule about literals in
# a Terraform configuration, so these are design rules informed by 1.18 rather
# than implementations of it.
#
# secret_data is marked sensitive in the provider schema, and how a sensitive
# attribute appears in `terraform show -json` decides which test can see it.
# Both cases are covered, so this rule holds either way.
#
#   (a) The literal is present in `after`. Seeing a string there is conclusive.
#   (b) The literal is withheld and only after_sensitive marks it. What is then
#       still visible is whether the value was known when the plan was made. A
#       known value can only have come from the configuration or a variable
#       file. A value produced at apply time is still unknown at this point.
#
# The two conditions are mutually exclusive, so a single violation is reported
# once.

deny contains msg if {
	some change in input.resource_changes
	change.type == "google_secret_manager_secret_version"
	is_string(object.get(change.change.after, "secret_data", null))
	msg := sprintf("[design] secrets: %v carries a literal secret value in the configuration", [change.address])
}

deny contains msg if {
	some change in input.resource_changes
	change.type == "google_secret_manager_secret_version"
	object.get(change.change.after, "secret_data", null) == null
	object.get(change.change, ["after_unknown", "secret_data"], false) == false
	msg := sprintf("[design] secrets: %v sets a secret value already known at plan time; it comes from the configuration", [change.address])
}

# CIS 1.11 - KMS keys must rotate within 90 days.
deny contains msg if {
	some change in input.resource_changes
	change.type == "google_kms_crypto_key"
	object.get(change.change.after, "rotation_period", null) == null
	msg := sprintf("[CIS 1.11] secrets: crypto key %v sets no rotation_period", [change.change.after.name])
}

deny contains msg if {
	some change in input.resource_changes
	change.type == "google_kms_crypto_key"
	period := object.get(change.change.after, "rotation_period", null)
	period != null
	seconds := to_number(trim_suffix(period, "s"))
	seconds > max_rotation_seconds
	msg := sprintf("[CIS 1.11] secrets: crypto key %v rotates every %vs, beyond the %vs maximum", [change.change.after.name, seconds, max_rotation_seconds])
}

# Data-holding buckets must use a customer-managed key.
deny contains msg if {
	some change in input.resource_changes
	change.type == "google_storage_bucket"
	count(object.get(change.change.after, "encryption", [])) == 0
	msg := sprintf("[design] secrets: bucket %v sets no customer-managed encryption key", [change.change.after.name])
}

# CIS 1.12 - separation of duties on KMS roles. The benchmark's condition is
# that no principal holds Cloud KMS Admin and any of the three CryptoKey
# Encrypter/Decrypter roles at the same time. Its audit reads the project IAM
# policy. A grant on a key ring or on a key confers the same role on what it
# covers, so this rule reads grants at all three levels.
kms_admin_role := "roles/cloudkms.admin"

kms_crypto_roles := {
	"roles/cloudkms.cryptoKeyEncrypterDecrypter",
	"roles/cloudkms.cryptoKeyEncrypter",
	"roles/cloudkms.cryptoKeyDecrypter",
}

kms_grant_types := {
	"google_project_iam_member",
	"google_kms_key_ring_iam_member",
	"google_kms_crypto_key_iam_member",
}

kms_admins contains member if {
	some change in input.resource_changes
	change.type in kms_grant_types
	change.change.after.role == kms_admin_role
	member := change.change.after.member
}

kms_key_users contains member if {
	some change in input.resource_changes
	change.type in kms_grant_types
	kms_crypto_roles[change.change.after.role]
	member := change.change.after.member
}

deny contains msg if {
	some member in kms_admins
	kms_key_users[member]
	msg := sprintf("[CIS 1.12] secrets: %v holds Cloud KMS Admin and a key encrypt or decrypt role; administering a key and using it are not separated", [member])
}

# Beyond the benchmark. The identity that reads the objects must not also hold
# decrypt on the key protecting them. CIS 1.12 is the nearest statement of the
# principle, but its condition is key administration held together with key
# use, not object read held together with decrypt. This is a design rule
# informed by 1.12 rather than an implementation of it.
storage_readers contains member if {
	some change in input.resource_changes
	change.type == "google_storage_bucket_iam_member"
	startswith(change.change.after.role, "roles/storage.object")
	member := change.change.after.member
}

decrypters contains member if {
	some change in input.resource_changes
	change.type == "google_kms_crypto_key_iam_member"
	contains(change.change.after.role, "Decrypter")
	member := change.change.after.member
}

deny contains msg if {
	some member in storage_readers
	decrypters[member]
	msg := sprintf("[design] secrets: %v holds both object read and key decrypt; encryption gives no separation", [member])
}

# CIS 1.10 - Cloud KMS keys must not be anonymously or publicly accessible.
# The same two principals that make a bucket public make a key public. A key
# readable by allUsers protects nothing, whatever else is done with it.
public_principals := {"allUsers", "allAuthenticatedUsers"}

deny contains msg if {
	some change in input.resource_changes
	change.type in {"google_kms_crypto_key_iam_member", "google_kms_key_ring_iam_member"}
	public_principals[change.change.after.member]
	msg := sprintf("[CIS 1.10] secrets: %v grants %v to %v; a key readable by the public protects nothing", [change.address, change.change.after.role, change.change.after.member])
}
