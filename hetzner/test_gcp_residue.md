# test_gcp_residue

Keeps the retired GCP estate out of the documents that describe how this repo
works today.

## What it checks

- `README.md`, `.gitignore`, `hetzner/Pulumi.yaml`, `hetzner/RUNBOOK-new-stack.md`
  and `hetzner/RUNBOOK-provision-host.md` do not name GCP, Cloud Run, Cloud
  Armor, Google Cloud or `gcloud`. A file that must name the retired cloud
  belongs in the history set below, not on this list.
- `hetzner/RUNBOOK-existing-stack-migration.md` opens, within its first five
  lines, with the banner that says the migration is finished. The runbook is
  kept because `hetzner/test_passphrase_probe_pattern.py` pins its gate lines,
  and the banner is what stops a finished procedure reading as a task.

## What it does not cover

The history set is named by hand, not scanned: `RUNBOOK-edge-state-move.md`,
`PULUMI-BACKEND-INVENTORY.md`, and the secrets-provider audit
(`scripts/audit-pulumi-secrets.py` and its inventory), which must name
`gcpkms://` to refuse it. Each is labelled as history or as a guard in its own
text. A new file that names the retired cloud is not caught until it is added
to `OPERATING_FILES`.

## Run

From the repository root: `python3 -m unittest hetzner.test_gcp_residue -v`.
