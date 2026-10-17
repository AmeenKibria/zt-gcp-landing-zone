#!/usr/bin/env bash
# Platform-layer test for the Zero Trust landing zone artifact.
#
# Read README.md first. Runs from your own machine with your own credentials
# (gcloud auth login and gcloud auth application-default login). Works with
# the bash 3.2 that ships with macOS. Needs terraform >= 1.5, gcloud, jq, curl.
#
# Every case is put through two routes. The gate route is the pipeline's:
# terraform plan, then the repository's policy set evaluated by Open Policy
# Agent. The platform route applies the same saved plan directly, as an
# engineer bypassing the pipeline would, and records what Google Cloud does.
# Expected outcomes are committed before the run (expected-platform.tsv and
# cases/*/expected*.txt); this script compares and records, it never judges.
#
# Raw output stays in out/<run>/raw and is never committed. A redacted copy,
# with organisation, folder, project, billing and account identifiers replaced
# by placeholders, is written to out/<run>/redacted for the thesis record.

set -u -o pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE" || exit 1
[ -f config.env ] || { echo "config.env not found. Copy config.env.example and fill it in."; exit 1; }
# shellcheck disable=SC1091
. ./config.env
: "${ORG_ID:?set ORG_ID in config.env}"
: "${BILLING_ACCOUNT:?set BILLING_ACCOUNT in config.env}"
: "${QUOTA_PROJECT:?set QUOTA_PROJECT in config.env}"
: "${PROJECT_ID:?set PROJECT_ID in config.env}"
REGION="${REGION:-europe-north1}"
ZONE="${ZONE:-europe-north1-a}"
WAIT_SECONDS="${WAIT_SECONDS:-900}"   # Organization Policy: up to 15 minutes to take effect
RETRY_SECONDS="${RETRY_SECONDS:-300}" # between retries while a policy change propagates
PHASES="${PHASES:-setup cases sequence}"
OPA_VERSION="v1.21.1"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$HERE/out/$RUN_ID"
RAW="$OUT/raw"
RED="$OUT/redacted"
mkdir -p "$RAW" "$RED"
POLICIES="$(cd "$HERE/.." && pwd)/policies"
CASES="$HERE/cases"
RESULTS="$RAW/results.tsv"
printf 'id\troute\texpected\tobserved\tmatch\n' > "$RESULTS"

export TF_VAR_org_id="$ORG_ID" TF_VAR_billing_account="$BILLING_ACCOUNT" \
       TF_VAR_quota_project="$QUOTA_PROJECT" TF_VAR_project_id="$PROJECT_ID" \
       TF_VAR_region="$REGION" TF_VAR_zone="$ZONE" TF_IN_AUTOMATION=1

log()    { printf '%s  %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$RAW/run.log"; }
record() { printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" >> "$RESULTS"
           log "RESULT $1 [$2] expected: $3 | observed: $4 | match: $5"; }
pause()  { log "waiting $1 s: $2"; sleep "$1"; }
has()    { [ "$1" = "$2" ] && echo yes || echo no; }

# ------------------------------------------------------------------ tools
install_opa() {
  if command -v opa >/dev/null 2>&1 && opa version 2>/dev/null | grep -q "^Version: ${OPA_VERSION#v}$"; then
    OPA="$(command -v opa)"; return
  fi
  local os arch asset base want have
  case "$(uname -s)" in Darwin) os=darwin ;; Linux) os=linux ;; *) echo "unsupported OS"; exit 1 ;; esac
  case "$(uname -m)" in arm64|aarch64) arch=arm64 ;; *) arch=amd64 ;; esac
  case "$os/$arch" in
    darwin/arm64) asset=opa_darwin_arm64_static ;;
    darwin/amd64) asset=opa_darwin_amd64 ;;
    linux/arm64)  asset=opa_linux_arm64_static ;;
    *)            asset=opa_linux_amd64_static ;;
  esac
  base="https://github.com/open-policy-agent/opa/releases/download/${OPA_VERSION}"
  mkdir -p "$HERE/bin"
  curl -fsSL -o "$HERE/bin/opa" "$base/$asset" && curl -fsSL -o "$HERE/bin/opa.sha256" "$base/$asset.sha256" \
    || { echo "Could not download OPA ${OPA_VERSION}. Install it yourself and re-run."; exit 1; }
  want="$(awk '{print $1}' "$HERE/bin/opa.sha256")"
  if command -v shasum >/dev/null 2>&1; then have="$(shasum -a 256 "$HERE/bin/opa" | awk '{print $1}')"
  else have="$(sha256sum "$HERE/bin/opa" | awk '{print $1}')"; fi
  [ "$want" = "$have" ] || { echo "OPA checksum mismatch"; exit 1; }
  chmod +x "$HERE/bin/opa"
  OPA="$HERE/bin/opa"
}

record_versions() {
  { echo "run: $RUN_ID"; uname -sm; terraform version | head -1; gcloud version 2>/dev/null | head -1
    "$OPA" version | head -1; jq --version; } > "$RAW/versions.txt" 2>&1
  log "tool versions recorded"
}

# ------------------------------------------------------------------ the two routes
# gate <case> <apply|destroy> <expected-file>
gate() {
  local c="$1" mode="$2" exp="$3" dir="$CASES/$1" tag="$1" flag="" n want m
  if [ "$mode" = destroy ]; then tag="$1-destroy"; flag="-destroy"; fi
  if ! ( cd "$dir" && terraform init -input=false -no-color ) > "$RAW/$tag.init.log" 2>&1; then
    record "$tag" gate "see expected file" "terraform init failed" no; return 1; fi
  if ! ( cd "$dir" && terraform plan $flag -input=false -no-color -out=tfplan.binary ) > "$RAW/$tag.plan.log" 2>&1; then
    record "$tag" gate "see expected file" "terraform plan failed" no; return 1; fi
  ( cd "$dir" && terraform show -json tfplan.binary > plan.json )
  if ! "$OPA" eval --format json --data "$POLICIES" --input "$dir/plan.json" 'data.main.deny' \
        > "$dir/result.json" 2> "$RAW/$tag.opa-error.log"; then
    record "$tag" gate "see expected file" "policy evaluation error" no; return 1; fi
  jq -r '.result[0].expressions[0].value[]?' "$dir/result.json" | LC_ALL=C sort > "$RAW/$tag.denials.txt"
  { sed "s/<PROJECT_ID>/$PROJECT_ID/g" "$dir/$exp" | grep -v '^$' | LC_ALL=C sort; } > "$RAW/$tag.expected.txt" || true
  n=$(grep -c . "$RAW/$tag.denials.txt" || true)
  want=$(grep -c . "$RAW/$tag.expected.txt" || true)
  if ( cd "$RAW" && diff -u "$tag.expected.txt" "$tag.denials.txt" ) > "$RAW/$tag.diff"; then m=yes; else m=no; fi
  record "$tag" gate "$want denial(s), exact lines in $tag.expected.txt" "$n denial(s)" "$m"
}

# platform <case> <refused|created> <string the refusal must name, or ->
platform() {
  local c="$1" want="$2" key="$3" dir="$CASES/$1" rc obs
  ( cd "$dir" && terraform apply -input=false -no-color tfplan.binary ) > "$RAW/$c.apply.log" 2>&1
  rc=$?
  if [ $rc -eq 0 ]; then obs=created
  elif [ "$key" != "-" ] && grep -Eq "$key" "$RAW/$c.apply.log"; then obs=refused
  else obs="failed for another reason (see $c.apply.log)"; fi
  if [ "$key" = "-" ]; then record "$c" platform "$want" "$obs" "$(has "$obs" "$want")"
  else record "$c" platform "$want, naming $key" "$obs" "$(has "$obs" "$want")"; fi
}

destroy_case() {
  ( cd "$CASES/$1" && terraform destroy -input=false -no-color -auto-approve ) > "$RAW/$1.destroy.log" 2>&1 \
    || log "WARNING: destroy of $1 failed; see $1.destroy.log and remove the resource by hand"
}

# ------------------------------------------------------------------ phases
phase_setup() {
  log "== baseline: policies already set on the organisation"
  gcloud org-policies list --organization="$ORG_ID" > "$RAW/baseline-org-policies.txt" 2>&1

  log "== setup stage 1: test folder and constraints"
  if ! ( cd setup/1-folder && terraform init -input=false -no-color && terraform apply -input=false -no-color -auto-approve ) \
      > "$RAW/setup-1.log" 2>&1; then abort "setup stage 1 failed; see setup-1.log"; fi
  FOLDER_ID="$(cd setup/1-folder && terraform output -raw folder_id)"
  export TF_VAR_folder_id="$FOLDER_ID"
  gcloud org-policies list --folder="$FOLDER_ID" > "$RAW/folder-policies.txt" 2>&1

  pause "$WAIT_SECONDS" "constraint propagation before the project enables Compute Engine"

  log "== setup stage 2: test project, APIs, network, folder firewall policy"
  if ! ( cd setup/2-project && terraform init -input=false -no-color && terraform apply -input=false -no-color -auto-approve ) \
      > "$RAW/setup-2.log" 2>&1; then abort "setup stage 2 failed; see setup-2.log"; fi

  log "== P-07 (CIS 3.1): networks in the new project"
  gcloud compute networks list --project="$PROJECT_ID" --format="value(name)" > "$RAW/p07-networks.txt" 2>&1
  if grep -qx default "$RAW/p07-networks.txt"; then obs="default network present"; else obs="no default network"; fi
  record p07-default-network platform "no default network" "$obs" "$(has "$obs" "no default network")"

  log "== effective policies on the test project"
  for k in compute.skipDefaultNetworkCreation compute.vmExternalIpAccess compute.vmCanIpForward \
           compute.requireShieldedVm sql.restrictPublicIp storage.uniformBucketLevelAccess \
           iam.managed.disableServiceAccountKeyCreation; do
    echo "--- $k"; gcloud org-policies describe "$k" --project="$PROJECT_ID" --effective 2>&1
  done > "$RAW/project-effective-policies.txt"
}

load_ids() {
  FOLDER_ID="$(cd setup/1-folder && terraform output -raw folder_id 2>/dev/null)"
  PROJECT_NUMBER="$(cd setup/2-project && terraform output -raw project_number 2>/dev/null)"
  export TF_VAR_folder_id="$FOLDER_ID"
}

phase_cases() {
  local c cis _gexp pexp key
  tail -n +2 expected-platform.tsv | while IFS="$(printf '\t')" read -r c cis _gexp pexp key; do
    log "== $c (CIS $cis)"
    gate "$c" apply expected.txt || { destroy_case "$c"; continue; }
    platform "$c" "$pexp" "$key"
    if [ "$c" = p08-firewall-ssh-open ]; then effective_firewalls; fi
    destroy_case "$c"
  done
}

effective_firewalls() {
  gcloud compute networks get-effective-firewalls zt-test-net --project="$PROJECT_ID" --format=json \
    > "$RAW/p08-effective-firewalls.json" 2>&1
  gcloud compute networks get-effective-firewalls zt-test-net --project="$PROJECT_ID" \
    > "$RAW/p08-effective-firewalls.txt" 2>&1
  local hier vpc obs
  hier=$(jq '[.firewallPolicys[]? | select(.type=="HIERARCHY") | .rules[]?
              | select(.action=="deny") | select([.match.layer4Configs[]?.ports[]?] | index("22"))] | length' \
         "$RAW/p08-effective-firewalls.json" 2>/dev/null || echo 0)
  vpc=$(jq '[.firewalls[]? | select(.name=="p08-allow-ssh-anywhere")] | length' \
         "$RAW/p08-effective-firewalls.json" 2>/dev/null || echo 0)
  if [ "${hier:-0}" -gt 0 ] && [ "${vpc:-0}" -gt 0 ]; then obs="folder deny for port 22 and the project allow rule both in effect"
  else obs="hierarchical deny rules found: ${hier:-0}; project rule found: ${vpc:-0}"; fi
  record p08-effective-firewalls platform "folder deny for port 22 and the project allow rule both in effect" "$obs" \
    "$(has "$obs" "folder deny for port 22 and the project allow rule both in effect")"
}

SA_NAME="r01-key-holder"
try_key() {  # try_key <log-tag>; prints the new key id on success
  local f; f="$(mktemp)"
  if gcloud iam service-accounts keys create "$f" --iam-account="$SA_NAME@$PROJECT_ID.iam.gserviceaccount.com" \
       --project="$PROJECT_ID" > "$RAW/$1.log" 2>&1; then
    rm -f "$f"; sed -n 's/.*created key \[\([0-9a-f]*\)\].*/\1/p' "$RAW/$1.log"; return 0
  fi
  rm -f "$f"; return 1
}
delete_key() {
  gcloud iam service-accounts keys delete "$1" --iam-account="$SA_NAME@$PROJECT_ID.iam.gserviceaccount.com" \
    --project="$PROJECT_ID" --quiet >> "$RAW/key-deletions.log" 2>&1
}
user_keys() {
  gcloud iam service-accounts keys list --iam-account="$SA_NAME@$PROJECT_ID.iam.gserviceaccount.com" \
    --project="$PROJECT_ID" --managed-by=user --format="value(name.basename())" 2>> "$RAW/key-list.log"
}

phase_sequence() {
  local k1 k obs i n
  log "== override and retroactivity sequence (CIS 1.5)"
  gcloud iam service-accounts create "$SA_NAME" --display-name="R-01 key holder" --project="$PROJECT_ID" \
    > "$RAW/r00-create-sa.log" 2>&1

  # R-00: control. The folder constraint is in effect, so key creation is refused.
  if k=$(try_key r00-before-override); then obs=created; delete_key "$k"; else obs=refused; fi
  record r00-key-before-override platform refused "$obs" "$(has "$obs" refused)"

  # O-02: switch the constraint off at project level with enforce = FALSE.
  gate o02-override-false apply expected.txt
  platform o02-override-false created "-"
  pause "$WAIT_SECONDS" "override propagation"

  # R-01: with the override in effect, a key can be created. Keep it (K1).
  k1=""
  for i in 1 2 3; do
    if k1=$(try_key "r01-after-override-$i"); then break; fi
    k1=""; pause "$RETRY_SECONDS" "override not yet in effect (attempt $i)"
  done
  if [ -n "$k1" ]; then obs=created; else obs=refused; fi
  record r01-key-after-override platform created "$obs" "$(has "$obs" created)"

  # O-03: the same switch-off written as a reset. Plan only; a known gap.
  gate o03-override-reset apply expected.txt

  # O-04: remove the override. The gate does not judge deletions.
  gate o02-override-false destroy expected-destroy.txt
  ( cd "$CASES/o02-override-false" && terraform apply -input=false -no-color tfplan.binary ) \
    > "$RAW/o02-override-false-destroy.apply.log" 2>&1 && obs=applied || obs="failed"
  record o04-override-removed platform applied "$obs" "$(has "$obs" applied)"
  pause "$WAIT_SECONDS" "re-enforcement propagation"

  # R-02: enforcement is back, so a new key is refused.
  obs=created
  for i in 1 2 3; do
    if k=$(try_key "r02-after-removal-$i"); then delete_key "$k"; pause "$RETRY_SECONDS" "enforcement not yet back (attempt $i)"
    else obs=refused; break; fi
  done
  record r02-key-after-removal platform refused "$obs" "$(has "$obs" refused)"

  # R-03: the key created while the override held is still there.
  user_keys > "$RAW/r03-user-managed-keys.txt"
  if [ -n "$k1" ] && grep -q "$k1" "$RAW/r03-user-managed-keys.txt"; then obs="existing key survives"; else obs="existing key not found"; fi
  record r03-existing-key platform "existing key survives" "$obs" "$(has "$obs" "existing key survives")"

  # R-04: posture reads of what exists.
  for i in 1 2 3 4 5; do
    gcloud asset search-all-resources --scope="projects/$PROJECT_ID" \
      --asset-types="iam.googleapis.com/ServiceAccountKey" --format=json > "$RAW/r04-asset-inventory.json" 2>&1
    if [ -n "$k1" ] && grep -q "$k1" "$RAW/r04-asset-inventory.json"; then break; fi
    pause "$RETRY_SECONDS" "Cloud Asset Inventory not yet showing the key (attempt $i)"
  done
  if [ -n "$k1" ] && grep -q "$k1" "$RAW/r04-asset-inventory.json"; then obs="key listed"; else obs="key not listed"; fi
  record r04-asset-inventory posture "key listed" "$obs" "$(has "$obs" "key listed")"

  printf 'name: projects/%s/policies/iam.managed.disableServiceAccountKeyCreation\nspec:\n  rules:\n  - enforce: true\n' \
    "$PROJECT_ID" > "$RAW/r05-simulated-policy.yaml"
  gcloud policy-intelligence simulate orgpolicy --organization="$ORG_ID" --policies="$RAW/r05-simulated-policy.yaml" \
    --billing-project="$PROJECT_ID" --format=json > "$RAW/r05-policy-simulator.json" 2>&1
  if [ -n "$k1" ] && grep -q "$k1" "$RAW/r05-policy-simulator.json"; then obs="key reported as a violation"
  elif grep -qi "ServiceAccountKey" "$RAW/r05-policy-simulator.json"; then obs="a service account key reported as a violation"
  else obs="no violation reported"; fi
  record r05-policy-simulator posture "key reported as a violation" "$obs" "$(has "$obs" "key reported as a violation")"

  log "== cleanup of the sequence"
  for k in $(user_keys); do delete_key "$k"; done
  gcloud iam service-accounts delete "$SA_NAME@$PROJECT_ID.iam.gserviceaccount.com" --project="$PROJECT_ID" --quiet \
    >> "$RAW/key-deletions.log" 2>&1
}

# ------------------------------------------------------------------ redaction and summary
escape() { printf '%s' "$1" | sed 's/[][\.*^$/]/\\&/g'; }

redact_all() {
  local account domain f args
  account="$(gcloud config get-value account 2>/dev/null)"
  domain="${account#*@}"
  args=""
  for pair in "PROJECT_NUMBER:${PROJECT_NUMBER:-}" "FOLDER_ID:${FOLDER_ID:-}" "ORG_ID:$ORG_ID" \
              "BILLING_ACCOUNT:$BILLING_ACCOUNT" "QUOTA_PROJECT:$QUOTA_PROJECT" "PROJECT_ID:$PROJECT_ID" \
              "USER:$account" "DOMAIN:$domain" "HOME:$HOME" "LOCAL_USER:$(id -un)"; do
    name="${pair%%:*}"; value="${pair#*:}"
    [ -n "$value" ] && args="$args -e s/$(escape "$value")/<$name>/g"
  done
  for f in "$RAW"/*; do
    [ -f "$f" ] || continue
    # shellcheck disable=SC2086
    sed $args -E -e 's/[0-9a-f]{40}/<KEY_ID>/g' "$f" > "$RED/$(basename "$f")"
  done
  log "redacted copies written to out/$RUN_ID/redacted"
}

summary() {
  local total ok
  total=$(($(wc -l < "$RESULTS") - 1))
  ok=$(awk -F'\t' 'NR>1 && $5=="yes"' "$RESULTS" | wc -l | tr -d ' ')
  { echo "# Platform-layer test, run $RUN_ID"; echo
    echo "$ok of $total results matched the outcome written down before the run."; echo
    echo "| id | route | expected | observed | match |"; echo "|---|---|---|---|---|"
    tail -n +2 "$RESULTS" | awk -F'\t' '{printf "| %s | %s | %s | %s | %s |\n", $1, $2, $3, $4, $5}'
  } > "$RAW/summary.md"
  log "$ok of $total results matched; see summary.md"
}

abort() { log "STOPPED: $1"; load_ids; summary; redact_all; exit 1; }

# ------------------------------------------------------------------ main
install_opa
record_versions
for p in $PHASES; do
  case "$p" in
    setup)    phase_setup ;;
    cases)    load_ids; phase_cases ;;
    sequence) load_ids; phase_sequence ;;
    *) log "unknown phase $p" ;;
  esac
done
load_ids
summary
redact_all
log "done. Send the folder out/$RUN_ID/redacted (not raw). Run ./teardown.sh when the results are checked."
