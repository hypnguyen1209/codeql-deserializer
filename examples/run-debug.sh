#!/usr/bin/env bash
# Deep-debug runner (Linux/macOS). See run-debug.ps1 for details.
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
command -v codeql >/dev/null || { echo "codeql CLI not on PATH"; exit 1; }
WORK="$(mktemp -d)"

summarize() {
  local sarif="$1" label="$2"
  echo; echo "===== $label ====="
  python3 - "$sarif" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
from collections import Counter
c=Counter(r["ruleId"] for r in d["runs"][0]["results"])
for k in sorted(c): print(f"  {k:<45} {c[k]}")
PY
}

JDB="$WORK/java-db"
codeql database create "$JDB" --language=java --source-root="$ROOT/examples/java" \
  --command="$ROOT/examples/java/build.sh" --overwrite >/dev/null
codeql database analyze "$JDB" "$ROOT/java/suites/java-deserialization.qls" \
  --format=sarif-latest --output="$WORK/java.sarif" --search-path="$ROOT/java" >/dev/null
summarize "$WORK/java.sarif" "Java: our suite (examples/java)"

PDB="$WORK/py-db"
codeql database create "$PDB" --language=python --source-root="$ROOT/examples/python" --overwrite >/dev/null
codeql database analyze "$PDB" "$ROOT/python/suites/python-deserialization.qls" \
  --format=sarif-latest --output="$WORK/py.sarif" --search-path="$ROOT/python" >/dev/null
summarize "$WORK/py.sarif" "Python: our suite (examples/python)"
