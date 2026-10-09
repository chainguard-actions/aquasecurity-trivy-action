<!-- markdownlint-disable -->

# Hardening Report: aquasecurity--trivy-action/v0.36.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **aquasecurity--trivy-action/v0.36.0** was hardened automatically. 4 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### unpinned-uses (severity: high)

workflow.yml contains three unpinned `uses:` references that use tags or branch names instead of full 40-character commit SHAs:
- `actions/checkout@v3` (tag)
- `aquasecurity/trivy-action@master` (branch)
- `github/codeql-action/upload-sarif@v3` (tag)
These are vulnerable to supply-chain attacks if the referenced tag or branch is moved.

Locations:

- `workflow.yml:12`
- `workflow.yml:19`
- `workflow.yml:30`

### script-injection (severity: high)

Sub-rule (a): A `${{ ... }}` expression is interpolated directly inside a `run:` shell command string in workflow.yml. The step 'Build an image from Dockerfile' uses `${{ github.sha }}` directly in the run block: `docker build -t docker.io/my-organization/my-app:${{ github.sha }} .`. Any `${{ }}` expression inside a run: block undergoes YAML template substitution before the shell sees it, making it a script-injection risk.

Locations:

- `workflow.yml:16`

### permissions (severity: medium)

workflow.yml has no top-level `permissions:` key and the single job 'build' also has no `permissions:` key. This means the workflow runs with the default (potentially broad) GitHub token permissions. A minimal explicit permissions block should be added.

Locations:

- `workflow.yml:1`

### github-env-injection (severity: high)

In action.yaml, the 'Set GitHub Path' step writes the env var `$GITHUB_ACTION_PATH` (sourced from `${{ github.action_path }}` via the env: block) directly to `$GITHUB_PATH` without the required sanitization step (`printf '%s' ... | tr -d '\n\r'`). The run block is: `echo "$GITHUB_ACTION_PATH" >> $GITHUB_PATH`. Even though `github.action_path` is GitHub-controlled, the check requires sanitization before any write to special environment files when the source is not a literal computed in the same run block.

Locations:

- `action.yaml:161`

## Iteration Notes

### Iteration 1

**Fixes applied:** unpinned-uses, script-injection, permissions, github-env-injection

**Notes:**

Fixed all four findings:
1. unpinned-uses: Pinned actions/checkout@v3 to SHA a37ce9120846195fa4ece8f58b268e6043cb2f26, aquasecurity/trivy-action@master to SHA c03d123cb480c08c69b054af418ea5e69fe6e57e, and github/codeql-action/upload-sarif@v3 to SHA 9f759ee644a3e7c15c1390abf49868036c00067b in workflow.yml.
2. script-injection: Moved ${{ github.sha }} out of the run block into the step's env block as GITHUB_SHA, referencing it as $GITHUB_SHA in the shell command.
3. permissions: Added top-level permissions block with 'contents: read' (for checkout) and 'security-events: write' (for uploading SARIF to GitHub Security tab).
4. github-env-injection: Updated the 'Set GitHub Path' step in action.yaml to sanitize GITHUB_ACTION_PATH with 'printf "%s" | tr -d "\n\r"' before writing to $GITHUB_PATH.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed all three unquoted ${INPUT_TRIVYIGNORES//,/ } expansions in entrypoint.sh (lines 28, 47, 57). Replaced the pattern with a safe bash array: `IFS=',' read -ra _trivyignores_arr <<< "${INPUT_TRIVYIGNORES}"` splits on commas without glob expansion. Both for-loops now iterate over `"${_trivyignores_arr[@]}"` (properly double-quoted), and the yaml_file extraction uses `"${_trivyignores_arr[0]}"` instead of the unquoted echo/awk pipeline. This prevents word-splitting and glob expansion on the attacker-controllable input.

