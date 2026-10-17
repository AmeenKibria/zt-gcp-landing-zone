# Zero Trust GCP landing zone — policy enforcement artifact

Companion artifact for a Master's thesis on embedding Zero Trust controls into a
Google Cloud Platform landing zone and enforcing them at deployment time.

The repository holds a Rego policy set, the configurations it is evaluated
against, and three workflows that run on every pull request:

- **Policy check** plans each configuration in a sandbox project and evaluates
  the plan against the policy set. Non-compliant configurations are expected to
  be blocked, so **a failed check is the expected result** for them. Compliant
  configurations are expected to pass with no denial. Every configuration also
  states its exact expected denials in `expected.txt`, and the job reports
  whether the output matched.
- **Policy unit tests** run `opa test` over hand-written plan fragments for every
  rule: violating and compliant cases, boundary values, deletions, data sources,
  unknown values and IAM bindings. Tests named `test_gap_*` assert a known limit.
- **Independent scan** runs KICS, an open-source scanner with its own query set,
  over the same configurations, so its findings can be compared with the gate's.

## Layout

```
.github/workflows/policy-check.yml      plan, then evaluate, one job per configuration
.github/workflows/policy-tests.yml      opa test with coverage
.github/workflows/independent-scan.yml  KICS over the same configurations
bootstrap/                              one-time federation setup, run by hand
policies/                               the Rego policy set, by domain; lib.rego holds shared readers
tests/                                  unit tests for every rule
scenarios/ts-*                          six non-compliant threat scenarios
scenarios/tc-*                          a compliant twin of each threat scenario
scenarios/ts-07a, ts-07b                one violation split across two plans
scenarios/tx-01-rule-coverage           one instance of each rule the threat scenarios do not reach
```

## Configurations

| Directory | Expected | What it holds | CIS v5.0.0 exercised |
|---|---|---|---|
| ts-01 | deny | Owner granted to a person; impersonation granted to an individual; the impersonated account holds Owner | 1.6 |
| ts-02 | deny | User-managed key; provider with no attribute condition; binding whose scope is unknown at plan time | 1.5 |
| ts-03 | deny | Bucket granted to allUsers, no uniform access, no public access prevention, no customer-managed key | 5.1, 5.2 |
| ts-04 | deny | SSH and RDP open to 0.0.0.0/0; service account holding an admin role; subnet without flow logs | 1.6, 3.6, 3.7, 3.10 |
| ts-05 | deny | Audit logging narrowed; an account exempted | 2.1 |
| ts-06 | deny | Literal secret; key without rotation and readable by anyone; bucket without customer-managed key; reader holding decrypt; key administrator who can also use the key | 1.10, 1.11, 1.12 |
| tc-01 … tc-06 | allow | The compliant form of each threat scenario | none |
| ts-07a, ts-07b | allow | Cloud KMS Admin in one plan, encrypt/decrypt for the same person in another; each half is compliant alone | 1.12 (not visible to one plan) |
| tx-01 | deny | Constraint switched off; project-level impersonation; viewer; pool-wide principal set; 365-day rotation; public bucket through a binding; SSH inside a port range; database port open; flow-log sampling below 100% | 1.5, 1.7, 1.11, 3.6, 3.10, 5.1 |

CIS identifiers from the Google Cloud Platform Foundation Benchmark v5.0.0. The
exact denials for each directory are in its `expected.txt`.

## Tool versions

Terraform 1.9.8 and Open Policy Agent v1.21.1 are pinned in the workflows, and
the OPA binary is checked against its published SHA-256 before use. The Google
provider is constrained to `~> 6.0`; the version installed is printed by
`terraform init`. KICS runs from the image `checkmarx/kics:v2.2.0`, and the job
records the image digest.

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

5. Open a pull request. Fifteen policy-check jobs run: the seven non-compliant
   configurations fail with their denials, and the eight compliant ones pass.
   The unit tests and the independent scan run alongside.

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

## Running locally

```bash
# unit tests, no cloud access needed
opa test policies tests --verbose

# one configuration against the policy set
cd scenarios/ts-03-public-bucket
terraform init
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > plan.json
opa eval --format pretty --data ../../policies --input plan.json 'data.main.deny'
```

## Known limits

The gate reads one plan. It cannot see a violation split across two changes
(ts-07a/b), decide that something is absent, read an authoritative
`*_iam_policy` resource, or read a legacy object ACL. It does not judge
resources that are deleted, left unchanged or only read as data sources;
existing state is the concern of a posture scanner. Each of these is stated in
a `test_gap_*` unit test or in a scenario, so it is visible rather than assumed.

## Anonymisation

No organisation name, domain, production project identifier or personnel name
belongs in this repository. Country folders in the thesis figures carry
placeholder names. The sandbox is a personal project, unconnected to any
production environment.
