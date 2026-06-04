# Hardening Report: aquasecurity--trivy-action/v0.35.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `ff50f15e4b79bfbf764dafdfd2579175a6ea9771`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **aquasecurity--trivy-action/v0.35.0** was hardened automatically. 4 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

The `run:` block in workflow.yml directly interpolates `${{ github.sha }}` (a github.* expression) inside the shell command string: `docker build -t docker.io/my-organization/my-app:${{ github.sha }} .`. Expressions should be assigned to an environment variable first and then referenced as `$ENV_VAR` in the shell command.

Locations:

- `workflow.yml:15`

### unpinned-uses (severity: high)

workflow.yml contains three `uses:` references pinned to mutable tags/branches instead of full 40-character commit SHAs: `actions/checkout@v3`, `aquasecurity/trivy-action@master`, and `github/codeql-action/upload-sarif@v3`. These are vulnerable to supply-chain attacks if the referenced tag or branch is moved.

Locations:

- `workflow.yml:12`
- `workflow.yml:19`
- `workflow.yml:30`

### missing-permissions (severity: medium)

workflow.yml has no top-level `permissions:` key and the `build` job also has no job-level `permissions:` key. Without explicit permissions, the workflow runs with the default (potentially broad) token permissions.

Locations:

- `workflow.yml:1`

### github-env-injection (severity: high)

The 'Set GitHub Path' step in action.yaml writes `$GITHUB_ACTION_PATH` to `$GITHUB_PATH` without sanitization. The value is sourced from `${{ github.action_path }}` via an `env:` variable (`GITHUB_ACTION_PATH: ${{ github.action_path }}`), and then written directly with `echo "$GITHUB_ACTION_PATH" >> $GITHUB_PATH`. The required sanitization step (`printf '%s' "$GITHUB_ACTION_PATH" | tr -d '\n\r'`) is absent before the write, making this vulnerable to newline injection into GITHUB_PATH.

Locations:

- `action.yaml:148`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, unpinned-uses, missing-permissions, github-env-injection

**Notes:**

Fixed all four findings in workflow.yml and action.yaml:
1. script-injection (workflow.yml line 15): Moved `${{ github.sha }}` into an `env:` block as `GITHUB_SHA` and referenced it as `$GITHUB_SHA` in the shell command.
2. unpinned-uses (workflow.yml lines 12, 19, 30): Pinned actions/checkout@v3 → @f43a0e5ff2bd294095638e18286ca9a3d1956744, aquasecurity/trivy-action@master → @bfa4b33a029b9aa80ddb784b45574c30e072c59e, github/codeql-action/upload-sarif@v3 → @d77b13a0df3134d64a457ea9003f600b09fa1c8a.
3. missing-permissions (workflow.yml line 1): Added top-level `permissions: { contents: read, security-events: write }` block.
4. github-env-injection (action.yaml line 148): Sanitized `$GITHUB_ACTION_PATH` with `printf '%s' "$GITHUB_ACTION_PATH" | tr -d '\n\r'` before writing to `$GITHUB_PATH`.

