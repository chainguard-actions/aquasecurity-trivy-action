<!-- markdownlint-disable -->

# Hardening Report: aquasecurity--trivy-action/v0.35.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **aquasecurity--trivy-action/v0.35.0** was hardened automatically. 4 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### unpinned-uses (severity: high)

workflow.yml contains three unpinned `uses:` references that use tags or branch names instead of full 40-character commit SHAs:
- `actions/checkout@v3` (tag)
- `aquasecurity/trivy-action@master` (branch)
- `github/codeql-action/upload-sarif@v3` (tag)
These mutable refs are vulnerable to supply-chain attacks if the upstream tag or branch is moved.

Locations:

- `workflow.yml:12`
- `workflow.yml:20`
- `workflow.yml:30`

### permissions (severity: medium)

workflow.yml has no top-level `permissions:` key and the `build` job also has no job-level `permissions:` key. Without explicit permissions, the workflow runs with the default (potentially broad) token permissions, violating least-privilege.

Locations:

- `workflow.yml:1`

### script-injection (severity: high)

Sub-rule (a): A `${{ ... }}` expression is interpolated directly inside a `run:` shell command string. In the 'Build an image from Dockerfile' step, `${{ github.sha }}` is embedded directly in the docker build command: `docker build -t docker.io/my-organization/my-app:${{ github.sha }} .`. Any GitHub Actions expression inside a `run:` block is substituted before the shell sees it, making it a script-injection risk.

Locations:

- `workflow.yml:16`

### github-env-injection (severity: high)

The 'Set GitHub Path' step in action.yaml writes the env var `$GITHUB_ACTION_PATH` (sourced from `${{ github.action_path }}` via the step's `env:` block) directly to `$GITHUB_PATH` without the required sanitization step (`printf '%s' "$VAR" | tr -d '\n\r'`). The command is: `echo "$GITHUB_ACTION_PATH" >> $GITHUB_PATH`. Routing through an `env:` variable does not sanitize the value; the sanitization pipeline is required before every write to a special environment file when the source is a github.* context value.

Locations:

- `action.yaml:161`

## Iteration Notes

### Iteration 1

**Fixes applied:** unpinned-uses, permissions, script-injection, github-env-injection

**Notes:**

Fixed all four findings in workflow.yml and action.yaml:
1. unpinned-uses: Pinned actions/checkout@v3 to SHA a37ce9120846195fa4ece8f58b268e6043cb2f26, aquasecurity/trivy-action@master to SHA c03d123cb480c08c69b054af418ea5e69fe6e57e, and github/codeql-action/upload-sarif@v3 to SHA 1190a975f95ce23525efb6a3fc21ea29567c1b52, all with tag comments.
2. permissions: Added top-level permissions block with 'contents: read' (for checkout) and 'security-events: write' (for uploading SARIF to GitHub Security tab).
3. script-injection: Moved ${{ github.sha }} in the 'Build an image from Dockerfile' run: step into an env: block as GITHUB_SHA, referenced as $GITHUB_SHA in the shell command.
4. github-env-injection: Fixed the 'Set GitHub Path' step in action.yaml to sanitize GITHUB_ACTION_PATH with 'printf "%s" | tr -d "\n\r"' before writing to $GITHUB_PATH, and quoted $GITHUB_PATH.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed all three unquoted expansions of INPUT_TRIVYIGNORES in entrypoint.sh:
1. First for loop (~line 29): Replaced `for f in ${INPUT_TRIVYIGNORES//,/ }` with `IFS=',' read -ra _trivyignores_arr <<< "${INPUT_TRIVYIGNORES}"` followed by `for f in "${_trivyignores_arr[@]}"` with per-element space trimming.
2. yaml_file extraction (~line 48): Replaced `echo ${INPUT_TRIVYIGNORES//,/ } | awk '{print $1}'` with `yaml_file="${_trivyignores_arr[0]# }"` using the already-split array.
3. Second for loop (~line 55): Replaced `for f in ${INPUT_TRIVYIGNORES//,/ }` with `for f in "${_trivyignores_arr[@]}"` with per-element space trimming.
All fixes prevent word splitting and glob expansion on attacker-controlled input while preserving the original comma-separated file list behavior.

