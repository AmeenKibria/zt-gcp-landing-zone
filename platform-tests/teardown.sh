#!/usr/bin/env bash
# Removes what run.sh created. Safe to run more than once.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE" || exit 1
# shellcheck disable=SC1091
. ./config.env
export TF_VAR_org_id="$ORG_ID" TF_VAR_billing_account="$BILLING_ACCOUNT" \
       TF_VAR_quota_project="$QUOTA_PROJECT" TF_VAR_project_id="$PROJECT_ID" \
       TF_VAR_region="${REGION:-europe-north1}" TF_VAR_zone="${ZONE:-europe-north1-a}" TF_IN_AUTOMATION=1
TF_VAR_folder_id="$(cd setup/1-folder && terraform output -raw folder_id 2>/dev/null)"
export TF_VAR_folder_id

for d in cases/*/; do
  if [ -f "$d/terraform.tfstate" ]; then
    echo "destroying $d"; ( cd "$d" && terraform destroy -input=false -no-color -auto-approve >/dev/null ) || echo "  check $d by hand"
  fi
done

SA="r01-key-holder@$PROJECT_ID.iam.gserviceaccount.com"
if gcloud iam service-accounts describe "$SA" --project="$PROJECT_ID" >/dev/null 2>&1; then
  for k in $(gcloud iam service-accounts keys list --iam-account="$SA" --project="$PROJECT_ID" --managed-by=user --format="value(name.basename())"); do
    gcloud iam service-accounts keys delete "$k" --iam-account="$SA" --project="$PROJECT_ID" --quiet
  done
  gcloud iam service-accounts delete "$SA" --project="$PROJECT_ID" --quiet
fi

echo "destroying the test project (it enters a 30-day pending-deletion state)"
( cd setup/2-project && terraform destroy -input=false -no-color -auto-approve ) || echo "  stage 2 destroy failed; check by hand"

echo "destroying the test folder and its constraints"
( cd setup/1-folder && terraform destroy -input=false -no-color -auto-approve ) \
  || echo "  The folder may refuse deletion while the project is pending deletion. It is empty and costs nothing; run this again later."
