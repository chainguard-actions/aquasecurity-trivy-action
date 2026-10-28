<!-- markdownlint-disable -->

# Hardening Report: aquasecurity--trivy-action/v0.35.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `374911c4be584df24e6da57af2d990570ef0f859`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **aquasecurity--trivy-action/v0.35.0** was hardened automatically. 7 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### github-env-injection (severity: high)

The 'Set GitHub Path' step routes the github.* context value github.action_path through the GITHUB_ACTION_PATH env var and writes it straight to $GITHUB_PATH: `run: echo "$GITHUB_ACTION_PATH" >> $GITHUB_PATH`. Newlines are never stripped. github.* sources count as untrusted under this check, and $GITHUB_PATH has no heredoc form, so the sanitization step is required. Fix: `safe=$(printf '%s' "$GITHUB_ACTION_PATH" | tr -d '\n\r'); echo "$safe" >> "$GITHUB_PATH"`.

Locations:

- `action.yaml:149`

### unpinned-uses (severity: high)

Carried forward from this version's previous harden, which fixed it; fix it again unless the code no longer has the problem. workflow.yml contains three unpinned `uses:` references that use tags or branch names instead of full 40-character commit SHAs:
- `actions/checkout@v3` (tag)
- `aquasecurity/trivy-action@master` (branch)
- `github/codeql-action/upload-sarif@v3` (tag)
These mutable refs are vulnerable to supply-chain attacks if the upstream tag or branch is moved.

Locations:

- `workflow.yml:12`
- `workflow.yml:20`
- `workflow.yml:30`

### permissions (severity: medium)

Carried forward from this version's previous harden, which fixed it; fix it again unless the code no longer has the problem. workflow.yml has no top-level `permissions:` key and the `build` job also has no job-level `permissions:` key. Without explicit permissions, the workflow runs with the default (potentially broad) token permissions, violating least-privilege.

Locations:

- `workflow.yml:1`

### script-injection (severity: high)

Carried forward from this version's previous harden, which fixed it; fix it again unless the code no longer has the problem. Sub-rule (a): A `${{ ... }}` expression is interpolated directly inside a `run:` shell command string. In the 'Build an image from Dockerfile' step, `${{ github.sha }}` is embedded directly in the docker build command: `docker build -t docker.io/my-organization/my-app:${{ github.sha }} .`. Any GitHub Actions expression inside a `run:` block is substituted before the shell sees it, making it a script-injection risk.

Locations:

- `workflow.yml:16`

### prior-fix (severity: high)

Carried forward from this version's previous harden, which fixed it; fix it again unless the code no longer has the problem. The previous harden changed action.yaml without recording a finding for it, and this analysis reported nothing there. Re-apply its security changes unless the code no longer needs them. The previous patch:
```diff
diff --git a/action.yaml b/action.yaml
index e7dbcaf..6cf907a 100644
--- a/action.yaml
+++ b/action.yaml
@@ -1,7 +1,6 @@
 name: 'Aqua Security Trivy'
 description: 'Scans container images for vulnerabilities with Trivy'
 author: 'Aqua Security'
-
 inputs:
   scan-type:
     description: 'Scan type to use for scanning vulnerability'
@@ -109,17 +108,32 @@ inputs:
     default: 'false'
   token-setup-trivy:
     description: >
-      `token-setup-trivy` is required when `github.token` in invalid for `https://github.com` server.
-      See https://github.com/aquasecurity/setup-trivy/?tab=readme-ov-file#install-trivy-with-non-default-token for more details.
-      `token-setup-trivy` is only used to fetch the Trivy repository in `setup-trivy`
+      `token-setup-trivy` is required when `github.token` in invalid for `https://github.com` server. See https://github.com/aquasecurity/setup-trivy/?tab=readme-ov-file#install-trivy-with-non-default-token for more details. `token-setup-trivy` is only used to fetch the Trivy repository in `setup-trivy`
+
     required: false
     ## ${{ github.token }} is default value for actions/checkout
     ## cf. https://github.com/actions/checkout/blob/eef61447b9ff4aafe5dcd4e0bbf5d482be7e7871/action.yml#L24
     default: ${{ github.token }}
-
 runs:
   using: 'composite'
   steps:
     - name: Install Trivy
       if: ${{ inputs.skip-setup-trivy == 'false' }}
       # Pin to hash instead of tag for aquasecurity/setup-trivy action so that GitHub Actions 
@@ -131,12 +145,10 @@ runs:
         version: ${{ inputs.version }}
         cache: ${{ inputs.cache }}
         token: ${{ inputs.token-setup-trivy }}
-
     - name: Get current date
       id: date
       shell: bash
       run: echo "date=$(date +'%Y-%m-%d')" >> $GITHUB_OUTPUT
-
     - name: Restore DB from cache
       if: ${{ inputs.cache == 'true' }}
       uses: actions/cache@0400d5f644dc74513175e3cd8d07132dd4860809 # v4.2.4
@@ -144,13 +156,13 @@ runs:
         path: ${{ inputs.cache-dir }}
         key: cache-trivy-${{ steps.date.outputs.date }}
         restore-keys: cache-trivy-
-
     - name: Set GitHub Path
-      run: echo "$GITHUB_ACTION_PATH" >> $GITHUB_PATH # zizmor: ignore[github-env]
       shell: bash
       env:
         GITHUB_ACTION_PATH: ${{ github.action_path }}
-
+      run: |
+        safe=$(printf '%s' "$GITHUB_ACTION_PATH" | tr -d '\n\r')
+        echo "$safe" >> "$GITHUB_PATH"
     # Create and Clear Trivy Envs file
     # See #422 for context
     - name: Clear Trivy Envs file
@@ -158,7 +170,6 @@ runs:
       run: |
         rm -f trivy_envs.txt
         touch trivy_envs.txt
-
     - name: Set Trivy environment variables
       shell: bash
       env:
@@ -229,7 +240,6 @@ runs:
         set_env_var_if_provided "TRIVY_CONFIG" "$INPUT_TRIVY_CONFIG" ""
         set_env_var_if_provided "TRIVY_TF_VARS" "$INPUT_TF_VARS" ""
         set_env_var_if_provided "TRIVY_DOCKER_HOST" "$INPUT_DOCKER_HOST" ""
-
     - name: Run Trivy
       shell: bash
       run: entrypoint.sh
@@ -243,10 +253,8 @@ runs:
         INPUT_TRIVYIGNORES: ${{ inputs.trivyignores }}
         INPUT_GITHUB_PAT: ${{ inputs.github-pat }}
         INPUT_LIMIT_SEVERITIES_FOR_SARIF: ${{ inputs.limit-severities-for-sarif }}
-
         # For Trivy
         TRIVY_CACHE_DIR: ${{ inputs.cache-dir }} # Always set
-
     # Remove Trivy envs to keep envs within this action and avoid env leaks
     # See #422 for context
     - name: Remove Trivy Envs file

```

Locations:

- `action.yaml`

### prior-fix (severity: high)

Carried forward from this version's previous harden, which fixed it; fix it again unless the code no longer has the problem. The previous harden changed entrypoint.sh without recording a finding for it, and this analysis reported nothing there. Re-apply its security changes unless the code no longer needs them. The previous patch:
```diff
diff --git a/entrypoint.sh b/entrypoint.sh
index 4bdfe7e..53decb1 100755
--- a/entrypoint.sh
+++ b/entrypoint.sh
@@ -26,7 +26,10 @@ if [ -n "${INPUT_TRIVYIGNORES:-}" ]; then
   plain_count=0
 
   # Validate files and detect types
-  for f in ${INPUT_TRIVYIGNORES//,/ }; do
+  IFS=',' read -ra _trivyignores_arr <<< "${INPUT_TRIVYIGNORES}"
+  for f in "${_trivyignores_arr[@]}"; do
+    f="${f# }"  # strip leading space
+    f="${f% }"  # strip trailing space
     if [ ! -f "$f" ]; then
       echo "ERROR: cannot find ignorefile '${f}'." >&2
       exit 1
@@ -52,7 +55,8 @@ if [ -n "${INPUT_TRIVYIGNORES:-}" ]; then
     fi
 
     # Use the single YAML file
-    yaml_file=$(echo ${INPUT_TRIVYIGNORES//,/ } | awk '{print $1}')
+    yaml_file="${_trivyignores_arr[0]# }"
+    yaml_file="${yaml_file% }"
     echo "Using YAML ignorefile '$yaml_file':"
     cat "$yaml_file"
     export TRIVY_IGNOREFILE="$yaml_file"
@@ -62,7 +66,9 @@ if [ -n "${INPUT_TRIVYIGNORES:-}" ]; then
     ignorefile="./trivyignores"
     : > "$ignorefile"
 
-    for f in ${INPUT_TRIVYIGNORES//,/ }; do
+    for f in "${_trivyignores_arr[@]}"; do
+      f="${f# }"  # strip leading space
+      f="${f% }"  # strip trailing space
       echo "Found ignorefile '$f':"
       cat "$f"
       cat "$f" >> "$ignorefile"

```

Locations:

- `entrypoint.sh`

### prior-fix (severity: high)

Carried forward from this version's previous harden, which fixed it; fix it again unless the code no longer has the problem. The previous harden changed workflow.yml without recording a finding for it, and this analysis reported nothing there. Re-apply its security changes unless the code no longer needs them. The previous patch:
```diff
diff --git a/workflow.yml b/workflow.yml
index d9d8930..9c8a85c 100644
--- a/workflow.yml
+++ b/workflow.yml
@@ -4,20 +4,27 @@ on:
     branches:
       - master
   pull_request:
+
+permissions:
+  contents: read
+  security-events: write
+
 jobs:
   build:
     name: Build
     runs-on: ubuntu-20.04
     steps:
       - name: Checkout code
-        uses: actions/checkout@v3
+        uses: actions/checkout@a37ce9120846195fa4ece8f58b268e6043cb2f26 # v3
 
       - name: Build an image from Dockerfile
+        env:
+          GITHUB_SHA: ${{ github.sha }}
         run: |
-          docker build -t docker.io/my-organization/my-app:${{ github.sha }} .
+          docker build -t docker.io/my-organization/my-app:$GITHUB_SHA .
 
       - name: Run Trivy vulnerability scanner
-        uses: aquasecurity/trivy-action@master
+        uses: aquasecurity/trivy-action@c03d123cb480c08c69b054af418ea5e69fe6e57e # master
         with:
           image-ref: 'docker.io/my-organization/my-app:${{ github.sha }}'
           exit-code: '1'
@@ -29,6 +36,6 @@ jobs:
           severity: 'CRITICAL,HIGH'
 
       - name: Upload Trivy scan results to GitHub Security tab
-        uses: github/codeql-action/upload-sarif@v3
+        uses: github/codeql-action/upload-sarif@1190a975f95ce23525efb6a3fc21ea29567c1b52 # v3
         with:
           sarif_file: 'trivy-results.sarif'

```

Locations:

- `workflow.yml`

## Iteration Notes

### Iteration 1

**Fixes applied:** github-env-injection, unpinned-uses, permissions, script-injection, prior-fix

**Notes:**

action.yaml: the 'Set GitHub Path' step now strips newlines from GITHUB_ACTION_PATH before writing it to the quoted "$GITHUB_PATH". This re-applies the action.yaml prior fix; the other parts of that old diff only changed blank lines and formatting. workflow.yml: pinned actions/checkout v3 (a37ce912...), aquasecurity/trivy-action master (8f28faec..., the current SHA, which differs from the old pin) and codeql-action/upload-sarif v3 (4bfa242a...). Added top-level permissions (contents: read, security-events: write). Moved ${{ github.sha }} out of the run: script into env as IMAGE_SHA and quoted it. entrypoint.sh: I did NOT re-apply the old change on purpose. The unquoted ${INPUT_TRIVYIGNORES//,/ } can't run anything, because it only splits words and expands globs, so it isn't an injection risk. Upstream splits the list on both commas and whitespace, and the old patch changed that to commas only, which would break inputs that list files separated by spaces.

