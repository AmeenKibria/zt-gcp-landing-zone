package landingzone.secrets

# Zero Trust tenets 3 and 6 (Rose et al., 2020, pp. 6-7).
# CIS GCP Foundation Benchmark v5.0.0: 1.11, 1.12, 1.18.
#
# The separation rule below encodes a documented failure: at Capital One the
# data was encrypted, but the compromised role also held decrypt, so encryption
# provided no protection (Khan et al., 2022, Section 3.2). CIS 1.12 requires
# exactly this separation independently.

max_rotation_seconds := 7776000        # 90 days

# CIS 1.18 - secrets belong in Secret Manager, not in configuration.
deny contains msg if {
  some change in input.resource_changes
  change.type == "google_secret_manager_secret_version"
  value := change.change.after.secret_data
  is_string(value)
  not startswith(value, "${")
  msg := sprintf("ts-06 [CIS 1.18]: literal secret value committed for %v", [change.change.after.secret])
}

# CIS 1.11 - KMS keys must rotate within 90 days.
deny contains msg if {
  some change in input.resource_changes
  change.type == "google_kms_crypto_key"
  not change.change.after.rotation_period
  msg := sprintf("ts-06 [CIS 1.11]: crypto key %v has no rotation_period", [change.change.after.name])
}

deny contains msg if {
  some change in input.resource_changes
  change.type == "google_kms_crypto_key"
  period := change.change.after.rotation_period
  seconds := to_number(trim_suffix(period, "s"))
  seconds > max_rotation_seconds
  msg := sprintf("ts-06 [CIS 1.11]: crypto key %v rotates every %vs, beyond the %vs maximum", [change.change.after.name, seconds, max_rotation_seconds])
}

# Data-holding buckets must use a customer-managed key.
deny contains msg if {
  some change in input.resource_changes
  change.type == "google_storage_bucket"
  not change.change.after.encryption
  msg := sprintf("ts-06: bucket %v has no customer-managed encryption key", [change.change.after.name])
}

# CIS 1.12 - separation of duties on KMS roles.
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
  msg := sprintf("ts-06 [CIS 1.12]: %v holds both object read and key decrypt; encryption gives no separation", [member])
}
