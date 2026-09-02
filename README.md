# Zero Trust GCP landing zone — policy enforcement artifact

Companion artifact for a Master's thesis on embedding Zero Trust controls into a
Google Cloud Platform landing zone and enforcing them at deployment time.

Each scenario is a deliberately non-compliant Terraform configuration. The
pipeline plans it, evaluates the plan against the Rego policy set, and fails.
**A failed check is the expected result** — it is the evidence that enforcement
works.

## Layout

```
.github/workflows/policy-check.yml   plan, then evaluate, one job per scenario
bootstrap/                           one-time federation setup, run by hand
policies/                            the Rego policy set, by domain
scenarios/                           six non-compliant configurations
```

## Scenarios

| Scenario | Violation | Security area | NIST tenets | CIS v5.0.0 |
|---|---|---|---|---|
| ts-01 | Basic role and impersonation granted to a human | IAM | 3, 4 | 1.6, 1.7 |
| ts-02 | Downloadable service account key created | Secrets | 6 | 1.5 |
| ts-03 | Bucket public, no uniform bucket-level access | Storage | 2 | 5.1, 5.2 |
| ts-04 | SSH and RDP open to 0.0.0.0/0, broad admin role | Network | 2, 4 | 3.6, 3.7 |
| ts-05 | Audit logging narrowed, account exempted | Logging | 5, 7 | 2.1 |
| ts-06 | Secret in code, no CMEK, decrypt held by reader | Secrets and keys | 3, 6 | 1.11, 1.12, 1.18 |

Tenets from NIST SP 800-207, Section 2.1, pp. 6–7. CIS identifiers from the
Google Cloud Platform Foundation Benchmark v5.0.0.

## One-time setup

1. Sandbox project `zt-lz-sandbox` already exists.

2. Run the bootstrap by hand, with your own credentials:

   ```bash
   cd bootstrap
   terraform init
   terraform apply
   ```

   `github_repository` already defaults to `AmeenKibria/zt-gcp-landing-zone`.

3. Put the outputs into the repository's Actions **variables**
   (Settings → Secrets and variables → Actions → Variables):

   | Variable | Value |
   |---|---|
   | `GCP_PROJECT_ID` | `zt-lz-sandbox` |
   | `WIF_PROVIDER` | the `workload_identity_provider` output |
   | `WIF_SERVICE_ACCOUNT` | the `pipeline_service_account` output |

   Variables, not secrets — none of them is a credential. That is the point.

4. Enable the APIs the scenarios touch, once, in the sandbox:

   ```bash
   gcloud services enable \
     iam.googleapis.com iamcredentials.googleapis.com \
     cloudresourcemanager.googleapis.com storage.googleapis.com \
     compute.googleapis.com cloudkms.googleapis.com \
     secretmanager.googleapis.com sts.googleapis.com \
     --project zt-lz-sandbox
   ```

5. Open a pull request. Six jobs run, six fail, each listing the rules that fired.

## Why federation rather than a key

The policy set denies `google_service_account_key` (ts-02). A pipeline enforcing
that rule while authenticating with a downloaded key would contradict itself.
GitHub mints a short-lived OIDC token, GCP exchanges it, nothing long-lived is
stored. The `attribute_condition` in the bootstrap restricts the exchange to this
repository — without it, any GitHub repository could obtain these credentials.

The pipeline service account holds `roles/browser` only. It never applies
anything, so it needs no more than enough read access to resolve the project and
plan a set of creates.

`roles/viewer` would have been the obvious choice and it is the wrong one: the
policy set denies every basic role, `roles/viewer` included (CIS 1.6). Granting
it here would give the artifact a role its own gate forbids, and the only reason
that never surfaces is that the bootstrap is applied by hand and never passes
through the gate.

## Terraform state

Nothing in this repository configures a backend, so every directory uses local
state by default. That is deliberate, and it means two different things in the
two places it applies.

**`bootstrap/`** is applied for real, so its state is worth keeping. It records
the identity pool, the OIDC provider and the pipeline service account. Losing it
deletes nothing in GCP, but Terraform stops knowing those resources exist, and
the next apply either fails on "already exists" or has to be repaired by hand
with `terraform import`. Local state is acceptable for a one-off run.
`bootstrap/state-bucket.tf.example` creates a versioned GCS bucket if you would
rather the configuration survive the laptop.

**`scenarios/`** needs no backend at all. The scenarios are only ever planned,
never applied, so no infrastructure is tracked and there is no state to lose.
Each CI job starts from a clean runner and a clean checkout. Local state here is
the correct choice rather than a compromise.

State is excluded by `.gitignore` in both cases, since Terraform records
attribute values in it in clear text.

## Running one scenario locally

```bash
cd scenarios/ts-03-public-bucket
terraform init
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > plan.json
opa eval --format pretty --data ../../policies --input plan.json 'data.landingzone[_].deny'
```

## Status

- Provider schemas verified against the Terraform provider documentation for
  `google_storage_bucket`, `google_project_iam_audit_config` and
  `google_kms_crypto_key`. Other resource names are written from working
  knowledge and not independently checked.
- The Rego assumes the plan JSON shape from `terraform show -json`, with changes
  under `input.resource_changes`. Conventional, but confirm against real output.
- Rego uses v1 `contains` / `if` syntax.
- Every scenario declares its own provider, variables and dependencies, so each
  directory plans on its own.
- The landing zone modules themselves are not in this repository yet.

## Anonymisation

No organisation name, domain, production project identifier or personnel name
belongs in this repository. Country folders in the thesis figures are
`country-a … country-n`. The sandbox is a personal project, unconnected to any
production environment.
