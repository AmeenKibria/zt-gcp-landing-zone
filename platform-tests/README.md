# Platform-layer test

The pipeline evaluation shows what the gate decides about a plan. This test
shows what Google Cloud itself does with the same changes when they bypass the
gate, in a personal test organisation that is unconnected to the commissioning
organisation. It checks four claims the thesis makes about the platform layer:

1. An organisation policy constraint refuses a violating change whatever route
   it takes, including a change the gate never sees.
2. A constraint is not applied retroactively. A resource created while the
   constraint did not hold survives when the constraint returns, and only a
   read of what exists (the posture layer) reports it.
3. The platform's refusal holds only while the organisation policy
   administrator role stays where the design put it. An administrator can
   switch a constraint off below the level that sets it.
4. A hierarchical firewall policy on a folder denies traffic before a
   project's own firewall rules are reached.

Expected outcomes are written down before the run, as in the pipeline: the
gate's exact denial lines in `cases/*/expected*.txt` and the platform outcome
in `expected-platform.tsv`. `run.sh` compares and records; it does not judge.

## What runs

| Id | Change | Gate (plan + policy set) | Platform (same plan applied) | CIS |
|---|---|---|---|---|
| P-01 | user-managed service account key | denied | refused | 1.5 |
| P-02 | bucket without uniform bucket-level access | denied | refused | 5.2 |
| P-03 | VM with an external IP address | silent | refused | 4.9 |
| P-04 | VM that forwards IP traffic | silent | refused | 4.6 |
| P-05 | VM without Shielded VM features | silent | refused | 4.8 |
| P-06 | Cloud SQL instance with a public IP address | silent | refused | 6.5, 6.7 |
| P-07 | new project under the folder | n/a | no default network | 3.1 |
| C-01 | compliant VM (control) | silent | created, then deleted | - |
| P-08 | project rule opening SSH to 0.0.0.0/0 | denied | created; folder deny evaluated first | 3.6 |

The override and retroactivity sequence, on one throwaway service account:

| Id | Step | Expected |
|---|---|---|
| R-00 | create a key while the folder constraint holds | refused |
| O-02 | project policy sets the key constraint to `enforce: FALSE` | gate denies the plan; platform accepts it from a policy administrator |
| R-01 | create a key while the override holds (key K1) | created |
| O-03 | the same switch-off written as `reset: true` (plan only) | gate silent: a known gap, recorded |
| O-04 | remove the override (a deletion in the plan) | gate silent, because deletions are not judged; platform accepts |
| R-02 | create another key once enforcement is back | refused |
| R-03 | list user-managed keys | K1 survives |
| R-04 | Cloud Asset Inventory search | K1 listed |
| R-05 | Policy Simulator for the enforced constraint | K1 reported as a violation |

All constraints are set on a dedicated test folder, never on the organisation
node, so nothing else in the test organisation is affected. The design sets
them at organisation level; a folder binds its projects the same way.

## Before you run it

You need `terraform` (1.5 or later), `gcloud`, `jq` and `curl`. The script
downloads Open Policy Agent v1.21.1 and checks its published SHA-256, unless
that version is already on your PATH.

1. **Roles in the test organisation** (run as an organisation administrator;
   replace the placeholders, and use your own test identity):

   ```bash
   ORG_ID=000000000000; ME=user:you@example.com
   for r in roles/resourcemanager.folderAdmin roles/resourcemanager.projectCreator \
            roles/orgpolicy.policyAdmin roles/compute.orgFirewallPolicyAdmin \
            roles/compute.orgSecurityResourceAdmin roles/policysimulator.orgPolicyAdmin; do
     gcloud organizations add-iam-policy-binding "$ORG_ID" --member="$ME" --role="$r" --condition=None
   done
   gcloud billing accounts add-iam-policy-binding 000000-000000-000000 --member="$ME" --role=roles/billing.user
   ```

2. **A quota project.** User credentials need an existing project to carry API
   quota. Pick one in the test organisation and enable these APIs on it (none
   of them creates a network):

   ```bash
   gcloud services enable cloudresourcemanager.googleapis.com orgpolicy.googleapis.com \
     serviceusage.googleapis.com cloudbilling.googleapis.com --project=QUOTA_PROJECT
   ```

3. **Credentials:**

   ```bash
   gcloud auth login
   gcloud auth application-default login
   gcloud auth application-default set-quota-project QUOTA_PROJECT
   ```

4. **Configuration:** `cp config.env.example config.env` and fill it in.
   `config.env` is git-ignored.

## Run

```bash
./run.sh
```

It takes about 60 to 90 minutes, most of it waiting. Organization Policy
changes can take up to 15 minutes to take effect, so the script waits after
setting the constraints, after the override and after removing it. To rerun
only part: `PHASES="cases sequence" ./run.sh`.

When it finishes, copy `out/<run>/redacted/` into the thesis folder as
`logs/platform-run-1/`. Do not share `out/<run>/raw/`: it holds the real
organisation, folder, project and account identifiers.

Then remove everything with `./teardown.sh`.

## Cost and safety

Refused requests create nothing. The compliant VM (C-01) exists for about a
minute. If a request that should be refused succeeds, the script destroys the
resource straight away, and the Cloud SQL case is the only one where that would
cost more than a few cents. The sequence creates user-managed keys on a
throwaway service account in the test project on purpose. The script deletes
them, writes no key material to disk beyond a temporary file it removes at
once, and deletes the account.

## Anonymisation

Nothing here names an organisation, domain, project, billing account or
person. Identifiers live only in `config.env` and in `out/<run>/raw/`, both
git-ignored. The redacted copy replaces them with placeholders such as
`<ORG_ID>` and `<PROJECT_ID>`, and service account key IDs with `<KEY_ID>`.
