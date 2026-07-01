#!/usr/bin/env python3
"""
bench.py - recall/precision benchmark for the gadget queries on known chains.

Builds a buildless CodeQL DB per fixture, runs the gadget suite, and checks
which expected findings fire. Reports recall (known chains found) and precision
(safe control has no *dangerous* findings; gadget-entry is allowed since any
readObject is an entry point by definition).

Usage: python3 benchmark/bench.py
Requires the CodeQL CLI on PATH and: codeql pack install java/qlpack.yml
"""
import json
import os
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUITE = os.path.join(REPO, "java/suites/java-gadgets.qls")
SEARCH = os.path.join(REPO, "java")
DANGEROUS = ["gadget-chain", "gadget-dispatch", "novel-gadget", "known-gadget-class"]

CASES = {
    "cc1": {
        "desc": "commons-collections-style chain (readObject->LazyMap.get->ChainedTransformer->InvokerTransformer->Method.invoke->exec)",
        "must": ["gadget-chain", "gadget-dispatch", "known-gadget-class", "gadget-entry"],
    },
    "beanutils": {
        "desc": "commons-beanutils BeanComparator (compare->Templates.newTransformer)",
        "must": ["gadget-dispatch", "known-gadget-class"],
    },
    "safe": {
        "desc": "benign readObject (control, no dangerous action)",
        "must": [],
        "is_safe": True,
    },
}


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def find_javac():
    p = os.environ.get("JAVA_HOME")
    if p and os.path.exists(os.path.join(p, "bin", "javac")):
        return os.path.join(p, "bin", "javac")
    from shutil import which
    return which("javac") or "javac"


def build_and_analyze(codeql, src, label):
    # NOTE: use a real javac build (not buildless) so interface supertypes
    # (Map/Comparator) resolve - buildless under-resolves them and would miss
    # gadget-dispatch. This measures the QUERIES, not the extraction mode.
    db = os.path.join(tempfile.gettempdir(), "bench-db-" + label)
    if not (os.path.isdir(db) and os.path.exists(os.path.join(db, "codeql-database.yml"))):
        javac = find_javac()
        argfile = os.path.join(tempfile.gettempdir(), "bench-args-" + label + ".txt")
        java_files = []
        for root, _, files in os.walk(src):
            for f in files:
                if f.endswith(".java"):
                    java_files.append(os.path.join(root, f))
        open(argfile, "w", encoding="utf-8").write("\n".join(java_files))
        classes = os.path.join(tempfile.gettempdir(), "bench-classes-" + label)
        os.makedirs(classes, exist_ok=True)
        build_cmd = f'"{javac}" -d "{classes}" "@{argfile}"'
        r = run([codeql, "database", "create", db, "--language=java",
                 "--source-root=" + src, "--command=" + build_cmd, "--overwrite"])
        if r.returncode != 0:
            print(r.stderr, file=sys.stderr); return None
    sarif = os.path.join(tempfile.gettempdir(), "bench-" + label + ".sarif")
    r = run([codeql, "database", "analyze", db, SUITE,
             "--format=sarif-latest", "--output=" + sarif, "--search-path=" + SEARCH])
    if r.returncode != 0:
        print(r.stderr, file=sys.stderr); return None
    d = json.load(open(sarif, "r", encoding="utf-8"))
    return (d.get("runs") or [{}])[0].get("results", [])


def main():
    codeql = os.environ.get("CODEQL", "codeql")
    print(f"{'fixture':<12} {'recall':<8} fired rules")
    print("-" * 64)
    vuln_total = 0; vuln_hit = 0; safe_ok = 0; safe_total = 0
    for label, case in CASES.items():
        src = os.path.join(REPO, "benchmark", label, "src")
        results = build_and_analyze(codeql, src, label)
        if results is None:
            print(f"{label:<12} ERROR (see stderr)"); continue
        fired = set()
        for r in results:
            for m in case["must"]:
                if m in r.get("ruleId", ""):
                    fired.add(m)
        miss = [m for m in case["must"] if m not in fired]
        if case.get("is_safe"):
            safe_total += 1
            dangerous = [r for r in results if any(d in r.get("ruleId", "") for d in DANGEROUS)]
            ok = (len(dangerous) == 0)
            if ok: safe_ok += 1
            print(f"{label:<12} {'-':<8} {len(results)} findings (control: {'PASS' if ok else 'FAIL'}, dangerous={len(dangerous)})")
        else:
            vuln_total += 1
            hit = (len(miss) == 0)
            if hit: vuln_hit += 1
            print(f"{label:<12} {'HIT' if hit else 'MISS':<8} fired={sorted(fired)} miss={miss}")
        print(f"             {case['desc']}")
    print("-" * 64)
    recall = (vuln_hit / vuln_total * 100) if vuln_total else 0
    precision = (safe_ok / safe_total * 100) if safe_total else 0
    print(f"recall: {vuln_hit}/{vuln_total} vulnerable chains found ({recall:.0f}%)")
    print(f"precision (safe control, no dangerous findings): {safe_ok}/{safe_total} ({precision:.0f}%)")
    if vuln_hit < vuln_total or safe_ok < safe_total:
        sys.exit(1)


if __name__ == "__main__":
    main()