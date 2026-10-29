<!-- markdownlint-disable -->

# Hardening Report: aquasecurity--trivy-action/v0.36.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `374911c4be584df24e6da57af2d990570ef0f859`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **aquasecurity--trivy-action/v0.36.0** was hardened automatically. 3 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### github-env-injection (severity: high)

The 'Set GitHub Path' step writes a github.* context value to $GITHUB_PATH without the required sanitization. GITHUB_ACTION_PATH is set from ${{ github.action_path }} through env:, and the step runs `echo "$GITHUB_ACTION_PATH" >> $GITHUB_PATH` with no `printf '%s' ... | tr -d '\n\r'` before the write. Routing the value through env: does not clean it, and $GITHUB_PATH has no heredoc form, so any newline in the value would add an extra PATH entry. The zizmor ignore comment does not satisfy this check. Fix: safe=$(printf '%s' "$GITHUB_ACTION_PATH" | tr -d '\n\r'); echo "$safe" >> "$GITHUB_PATH".

Locations:

- `action.yaml:149`

### prior-fix (severity: high)

Carried forward from this version's previous harden, which fixed it; fix it again unless the code no longer has the problem. The previous harden changed entrypoint.sh without recording a finding for it, and this analysis reported nothing there. Re-apply its security changes unless the code no longer needs them. The previous patch:
```diff
diff --git a/entrypoint.sh b/entrypoint.sh
index f0fbfb4..5ad5552 100755
--- a/entrypoint.sh
+++ b/entrypoint.sh
@@ -25,8 +25,13 @@ if [ -n "${INPUT_TRIVYIGNORES:-}" ]; then
   yaml_count=0
   plain_count=0
 
+  # Safely tokenize the comma-separated list into an array
+  trivyignores_files=()
+  while IFS= read -r -d '' t; do trivyignores_files+=("$t"); done \
+    < <(printf '%s' "${INPUT_TRIVYIGNORES//,/ }" | xargs -r printf '%s\0')
+
   # Validate files and detect types
-  for f in ${INPUT_TRIVYIGNORES//,/ }; do
+  for f in "${trivyignores_files[@]}"; do
     if [ ! -f "$f" ]; then
       echo "ERROR: cannot find ignorefile '${f}'." >&2
       exit 1
@@ -52,7 +57,7 @@ if [ -n "${INPUT_TRIVYIGNORES:-}" ]; then
     fi
 
     # Use the single YAML file
-    yaml_file=$(echo ${INPUT_TRIVYIGNORES//,/ } | awk '{print $1}')
+    yaml_file="${trivyignores_files[0]}"
     echo "Using YAML ignorefile '$yaml_file':"
     cat "$yaml_file"
     export TRIVY_IGNOREFILE="$yaml_file"
@@ -62,7 +67,7 @@ if [ -n "${INPUT_TRIVYIGNORES:-}" ]; then
     ignorefile="./trivyignores"
     : > "$ignorefile"
 
-    for f in ${INPUT_TRIVYIGNORES//,/ }; do
+    for f in "${trivyignores_files[@]}"; do
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
index d9d8930..2340c73 100644
--- a/workflow.yml
+++ b/workflow.yml
@@ -4,20 +4,25 @@ on:
     branches:
       - master
   pull_request:
+permissions:
+  contents: read
+  security-events: write
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
+          MY_SHA: ${{ github.sha }}
         run: |
-          docker build -t docker.io/my-organization/my-app:${{ github.sha }} .
+          docker build -t docker.io/my-organization/my-app:"$MY_SHA" .
 
       - name: Run Trivy vulnerability scanner
-        uses: aquasecurity/trivy-action@master
+        uses: aquasecurity/trivy-action@6abccf398f78b4c337599c0656f933d91efb91a0 # master
         with:
           image-ref: 'docker.io/my-organization/my-app:${{ github.sha }}'
           exit-code: '1'
@@ -29,6 +34,6 @@ jobs:
           severity: 'CRITICAL,HIGH'
 
       - name: Upload Trivy scan results to GitHub Security tab
-        uses: github/codeql-action/upload-sarif@v3
+        uses: github/codeql-action/upload-sarif@ce5e7eeac396d720fe2d802714996c8ce561e311 # v3
         with:
           sarif_file: 'trivy-results.sarif'

```

Locations:

- `workflow.yml`

## Iteration Notes

### Iteration 1

**Fixes applied:** github-env-injection, prior-fix

**Notes:**

action.yaml: the 'Set GitHub Path' step now strips newlines before the write: safe=$(printf '%s' "$GITHUB_ACTION_PATH" | tr -d '\n\r'), then echo "$safe" >> "$GITHUB_PATH". The zizmor ignore comment is gone. entrypoint.sh: re-applied the prior fix. The trivyignores list is now split once into an array, and that array is used in place of the three unquoted ${INPUT_TRIVYIGNORES//,/ } expansions (the yaml_file pick is now ${trivyignores_files[0]}). One change from the previous patch: it used xargs, which reads quotes in the value. I used read -r -d '' -a instead, which splits on commas and whitespace and keeps quotes as plain text, as upstream's unquoted expansion did. Empty arrays are guarded so the script still works with set -u on bash 3.2. workflow.yml: re-applied the prior fix. It adds least-privilege permissions (contents: read, security-events: write) and moves github.sha into env for the docker build step. It also pins checkout, trivy-action and upload-sarif to commit SHAs I looked up, which match the previous patch.

