# Deep-debug runner: builds demo CodeQL databases and runs the deserialization
# packs, then prints a summary you can diff against docs/deep-debug.md.
#
# Requires the CodeQL CLI on PATH and the local packs installed:
#   codeql pack install java/qlpack.yml python/qlpack.yml
#
# Usage (from repo root):
#   powershell -ExecutionPolicy Bypass -File examples/run-debug.ps1
[CmdletBinding()] param()
$root = Split-Path -Parent $PSScriptRoot
$codeql = (Get-Command codeql -ErrorAction SilentlyContinue).Source
if (-not $codeql) { throw "codeql CLI not found on PATH" }
$work = Join-Path $env:TEMP "codeql-db-debug"
Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $work | Out-Null

function Summary($sarif, $label) {
  $s = Get-Content $sarif -Raw | ConvertFrom-Json
  Write-Output ""
  Write-Output "===== $label ====="
  $s.runs[0].results | Group-Object ruleId | Sort-Object Name | ForEach-Object {
    Write-Output ("  {0,-45} {1}" -f $_.Name, $_.Count)
  }
}

# --- Java ---
$jdb = Join-Path $work "java-db"
& $codeql database create $jdb --language=java --source-root="$root\examples\java" `
  --command="$root\examples\java\build.cmd" --overwrite 2>&1 | Out-Null
& $codeql database analyze $jdb "$root\java\suites\java-deserialization.qls" `
  --format=sarif-latest --output="$work\java.sarif" --search-path="$root\java" 2>&1 | Out-Null
Summary "$work\java.sarif" "Java: our suite (examples/java)"

# Official parity check (run once: codeql pack download codeql/java-queries)
$jq = Get-ChildItem "$env:USERPROFILE\.codeql\packages\codeql\java-queries" -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
if ($jq) {
  & $codeql database analyze $jdb (Join-Path $jq.FullName "Security\CWE\CWE-502\UnsafeDeserialization.ql") `
    --format=sarif-latest --output="$work\java-official.sarif" --search-path=$jq.FullName 2>&1 | Out-Null
  Summary "$work\java-official.sarif" "Java: official java/unsafe-deserialization (parity)"
}

# --- Python ---
$pdb = Join-Path $work "py-db"
& $codeql database create $pdb --language=python --source-root="$root\examples\python" --overwrite 2>&1 | Out-Null
& $codeql database analyze $pdb "$root\python\suites\python-deserialization.qls" `
  --format=sarif-latest --output="$work\py.sarif" --search-path="$root\python" 2>&1 | Out-Null
Summary "$work\py.sarif" "Python: our suite (examples/python)"
