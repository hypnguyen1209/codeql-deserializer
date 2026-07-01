#!/usr/bin/env python3
"""
hunt.py - daily-driver gadget/sink hunting helper for the codeql-db packs.

Builds a CodeQL database from a target (buildless by default - no build/deps
needed for Java) and runs the deserialization + gadget query suites, then prints
and writes a ranked report of findings.

Usage:
  python tools/hunt.py <target-src>                      # Java, full suite, buildless
  python tools/hunt.py <target-src> --mode gadgets        # gadget/ysoserial queries only
  python tools/hunt.py <target-src> --lang python
  python tools/hunt.py <target-src> --command "mvn -B compile"   # real build
  python tools/hunt.py <target-src> --db /path/to/existing.db    # reuse a DB
  python tools/hunt.py <target-src> --threads 4 --sarif out.sarif

Requires the CodeQL CLI on PATH and the local packs installed:
  codeql pack install java/qlpack.yml python/qlpack.yml
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SUITES = {
    ("java", "gadgets"): "java/suites/java-gadgets.qls",
    ("java", "sinks"):   "java/suites/java-deserialization.qls",
    ("java", "full"):    "java/suites/java-all.qls",
    ("python", "sinks"):  "python/suites/python-deserialization.qls",
    ("python", "full"):   "python/suites/python-deserialization.qls",
}
SEARCH = {"java": "java", "python": "python"}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "warning": 4, "info": 5}


def run(cmd):
    print("  $ " + " ".join(cmd), file=sys.stderr)
    return subprocess.run(cmd)


def build_db(codeql, lang, target, db, command):
    if os.path.isdir(db) and os.path.exists(os.path.join(db, "codeql-database.yml")):
        print(f"[hunt] reusing existing database at {db}", file=sys.stderr)
        return True
    cmd = [codeql, "database", "create", db, "--language=" + lang,
           "--source-root=" + target, "--overwrite"]
    if command:
        cmd += ["--command=" + command]
    elif lang == "java":
        cmd += ["--build-mode=none"]
    r = run(cmd)
    if r.returncode != 0:
        print(f"[hunt] ERROR: database create failed (code {r.returncode}).", file=sys.stderr)
        if lang == "java" and not command:
            print("[hunt] hint: pass --command 'mvn -B compile' / 'gradle compileJava' "
                  "for a real build, or ensure the source root is a buildable project.",
                  file=sys.stderr)
        return False
    return True


def analyze(codeql, db, suite, search, sarif, threads=None):
    cmd = [codeql, "database", "analyze", db, suite,
           "--format=sarif-latest", "--output=" + sarif, "--search-path=" + search]
    if threads:
        cmd += ["--threads=" + str(threads)]
    r = run(cmd)
    return r.returncode == 0


def parse_severity(msg):
    low = msg.lower()
    for s in ("critical", "high", "medium", "low"):
        if "[" + s + "]" in low:
            return s
    return "info"


def report(sarif, out_md, lang, mode, target):
    with open(sarif, "r", encoding="utf-8") as f:
        data = json.load(f)
    runs = data.get("runs") or []
    results = runs[0].get("results", []) if runs else []

    by_rule = {}
    for r in results:
        rid = r.get("ruleId", "?")
        locs = r.get("locations", [{}])
        pl = (locs[0] if locs else {}).get("physicalLocation", {})
        uri = pl.get("artifactLocation", {}).get("uri", "?")
        reg = pl.get("region", {})
        line = reg.get("startLine", "?")
        col = reg.get("startColumn", "")
        msg = (r.get("message", {}).get("text", "") or "").replace("\n", " ")
        sev = parse_severity(msg)
        by_rule.setdefault(rid, []).append((sev, uri, line, col, msg))

    lines = []
    lines.append(f"# Hunt report - {target}")
    lines.append(f"_language: {lang} | mode: {mode} | findings: {len(results)}_\n")
    total = len(results)
    if total == 0:
        lines.append("**No findings.**\n")
    for rid in sorted(by_rule):
        items = sorted(by_rule[rid], key=lambda x: SEV_ORDER.get(x[0], 9))
        lines.append(f"## {rid}  ({len(items)})\n")
        lines.append("| sev | location | message |")
        lines.append("|---|---|---|")
        for sev, uri, line, col, msg in items:
            short = uri.split("/")[-1]
            loc = f"{short}:{line}" + (f":{col}" if col else "")
            m = msg if len(msg) <= 120 else msg[:117] + "..."
            lines.append(f"| {sev} | `{loc}` | {m} |")
        lines.append("")

    text = "\n".join(lines)
    with open(out_md, "w", encoding="utf-8") as f:
        f.write(text)
    print(text)
    print(f"\n[hunt] report written to {out_md}", file=sys.stderr)
    print(f"[hunt] {total} findings across {len(by_rule)} rules", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description="CodeQL deserialization/gadget hunting helper.")
    ap.add_argument("target", help="source root to analyze")
    ap.add_argument("--lang", default="java", choices=["java", "python"])
    ap.add_argument("--mode", default="full", choices=["gadgets", "sinks", "full"])
    ap.add_argument("--db", default=None, help="reuse an existing CodeQL database dir")
    ap.add_argument("--command", default=None, help="build command (default: buildless for Java)")
    ap.add_argument("--codeql", default="codeql", help="path to codeql CLI")
    ap.add_argument("--out", default=None, help="report markdown path")
    ap.add_argument("--threads", type=int, default=None, help="CodeQL --threads=N")
    ap.add_argument("--sarif", default=None, help="also keep the SARIF at this path")
    args = ap.parse_args()

    suite = SUITES.get((args.lang, args.mode))
    if suite is None:
        print(f"[hunt] no gadget queries for {args.lang}; use --mode sinks/full.", file=sys.stderr)
        sys.exit(2)
    suite_path = os.path.join(REPO, suite)
    search = os.path.join(REPO, SEARCH[args.lang])

    db = args.db or os.path.join(tempfile.gettempdir(), "hunt-db")
    print(f"[hunt] language={args.lang} mode={args.mode} target={args.target}", file=sys.stderr)
    if not build_db(args.codeql, args.lang, args.target, db, args.command):
        sys.exit(1)
    sarif = os.path.join(tempfile.gettempdir(), "hunt.sarif")
    print(f"[hunt] running suite {suite}", file=sys.stderr)
    if not analyze(args.codeql, db, suite_path, search, sarif, args.threads):
        sys.exit(1)
    if args.sarif:
        shutil.copy(sarif, args.sarif)
        print(f"[hunt] SARIF kept at {args.sarif}", file=sys.stderr)
    out_md = args.out or os.path.join(os.getcwd(), "hunt-report.md")
    report(sarif, out_md, args.lang, args.mode, args.target)


if __name__ == "__main__":
    main()
