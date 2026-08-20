<!-- markdownlint-disable -->

# Hardening Report: aquasecurity--trivy-action/v0.35.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **aquasecurity--trivy-action/v0.35.0** was hardened automatically. 4 finding(s) were identified and resolved across 3 iteration(s).

## Findings Fixed

### unsafe-shell (severity: high)

Remote shell script is downloaded and piped directly to `sh` without first saving to a file. In .github/workflows/bump-trivy.yaml the Install Trivy step runs: `curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin "v${TRIVY_VERSION}"`. This allows a compromised or man-in-the-middle remote script to execute arbitrary code on the runner.

Locations:

- `.github/workflows/bump-trivy.yaml:36`

### unsafe-shell (severity: high)

Remote shell script is downloaded and piped directly to `sh` without first saving to a file. In .github/workflows/test.yaml the Install Trivy step runs: `curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v${{ env.TRIVY_VERSION }}`. This allows a compromised or man-in-the-middle remote script to execute arbitrary code on the runner.

Locations:

- `.github/workflows/test.yaml:42`

### script-injection (severity: high)

Rule (a) violation: `${{ env.TRIVY_VERSION }}` is directly interpolated inside a `run:` shell command string in the Install Trivy step. The `env.*` context is a workflow-controllable value that flows through YAML template substitution before the shell processes it, enabling script injection. Offending line: `curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v${{ env.TRIVY_VERSION }}`

Locations:

- `.github/workflows/test.yaml:42`

### github-env-injection (severity: high)

The 'Set GitHub Path' step writes `github.action_path` (a `github.*` context value) to `$GITHUB_PATH` without the required sanitization step. The env var `GITHUB_ACTION_PATH` is set to `${{ github.action_path }}` and then written directly: `echo "$GITHUB_ACTION_PATH" >> $GITHUB_PATH`. The required sanitization (`safe=$(printf '%s' "$GITHUB_ACTION_PATH" | tr -d '\n\r')`) is absent, allowing newline injection into the PATH environment file.

Locations:

- `action.yaml:125`

## Iteration Notes

### Iteration 1

**Fixes applied:** unsafe-shell, script-injection, github-env-injection

**Notes:**

Fixed 4 findings across 3 files:
1. bump-trivy.yaml (line 36): Replaced `curl ... | sh -s -- -b ...` with download-to-tempfile then `sh "$INSTALL_SCRIPT" -b ...` (dropped the '--' as required since we're no longer piping to sh -s).
2. test.yaml (line 42): Same unsafe-shell fix. Also moved `${{ env.TRIVY_VERSION }}` out of the run: shell string into the step's env: block as TRIVY_VERSION, referencing it as `$TRIVY_VERSION` in the shell script to fix the script-injection finding.
3. action.yaml (line 125): Fixed github-env-injection in the 'Set GitHub Path' step by adding sanitization: `safe=$(printf '%s' "$GITHUB_ACTION_PATH" | tr -d '\n\r')` before writing to $GITHUB_PATH.

### Iteration 2

**Fixes applied:** missing-permissions, script-injection, unpinned-uses

**Notes:**

Fixed all three findings in hardened/action/workflow.yml:
1. missing-permissions: Added top-level `permissions: contents: read` and `security-events: write` (the latter is needed for the upload-sarif step).
2. script-injection: Moved `${{ github.sha }}` in the 'Build an image from Dockerfile' run: block into an `env: IMAGE_TAG:` variable, referencing it as `$IMAGE_TAG` in the shell command.
3. unpinned-uses: Pinned all three uses references to full commit SHAs — actions/checkout@a37ce9120846195fa4ece8f58b268e6043cb2f26 (v3), aquasecurity/trivy-action@d2a0b60797ff03db6132bd4e2b293f9b37081297 (master), github/codeql-action/upload-sarif@f3712979fa5f215279b101dd0a2e3bdfb4353324 (v3).

### Iteration 3

**Fixes applied:** script-injection

**Notes:**

Fixed two unquoted expansions of INPUT_TRIVYIGNORES in entrypoint.sh:
1. Replaced the unquoted `for f in ${INPUT_TRIVYIGNORES//,/ }` loops (lines ~27 and ~63) with a safe array-based approach: `IFS=',' read -ra trivyignores_array <<< "${INPUT_TRIVYIGNORES}"` followed by `for f in "${trivyignores_array[@]}"`.
2. Replaced the unquoted `yaml_file=$(echo ${INPUT_TRIVYIGNORES//,/ } | awk '{print $1}')` (line ~55) with direct array index access: `yaml_file="${trivyignores_array[0]}"`.
These changes prevent shell metacharacters (glob patterns, word-splitting characters) in the INPUT_TRIVYIGNORES value from being interpreted by the shell.

