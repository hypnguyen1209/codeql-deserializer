#!/usr/bin/env python3
"""
find-gadget-deser.py - scoped deserialization/gadget chain finder for a JAR.

Given a compiled Java archive and an entry/start class, this tool:
  1. decompiles the jar to Java source (CFR),
  2. builds a buildless CodeQL database (no Maven/Gradle/deps needed; cached by
     jar sha256 so re-runs are fast),
  3. runs a generated reachability query scoped to the start class that reports
     chains  start-method -> ... -> dangerous sink  where "dangerous" is either
     a deserialization sink (ObjectInputStream.readObject, XStream, Kryo,
     Jackson, Hessian, ...) or an RCE gadget action (Runtime.exec, Method.invoke,
     JNDI lookup, ClassLoader.loadClass, ScriptEngine.eval, Templates.newTransformer, ...),
  4. prints and writes a ranked Markdown report.

Usage:
  python3 tools/find-gadget-deser.py --jar app.jar --start-class MainWebSpring
  python3 tools/find-gadget-deser.py --jar app.jar --start-class com.example.MainWebSpring --full
  python3 tools/find-gadget-deser.py --jar app.jar --start-class Main --threads 4 --sarif out.sarif --keep-decompiled

Requires:
  - CodeQL CLI on PATH; local packs installed: codeql pack install java/qlpack.yml
  - a Java runtime on PATH (to run the CFR decompiler) - or set JAVA_HOME
  - internet on first run to fetch the CFR decompiler into tools/.cache (or pass --cfr)
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CFR_URL = "https://repo1.maven.org/maven2/org/benf/cfr/0.152/cfr-0.152.jar"
TEMPLATE = os.path.join(REPO, "java", "_generated", "_ReachableFromStartTemplate.ql")
SEARCH = os.path.join(REPO, "java")
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "deserialization": 0, "info": 4}


def find_java():
    p = os.environ.get("JAVA_HOME")
    if p and os.path.exists(os.path.join(p, "bin", "java")):
        return os.path.join(p, "bin", "java")
    from shutil import which
    return which("java")


def get_cfr(override):
    if override:
        return override
    cache = os.path.join(REPO, "tools", ".cache")
    os.makedirs(cache, exist_ok=True)
    cfr = os.path.join(cache, "cfr.jar")
    if not os.path.exists(cfr):
        print(f"[find-gadget-deser] downloading CFR decompiler -> {cfr}", file=sys.stderr)
        urllib.request.urlretrieve(CFR_URL, cfr)
    return cfr


def decompile(java, cfr, jar, outdir):
    if os.path.isdir(outdir):
        shutil.rmtree(outdir)
    r = subprocess.run([java, "-jar", cfr, jar, "--outputdir", outdir],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout); print(r.stderr, file=sys.stderr)
        print("[find-gadget-deser] ERROR: CFR decompilation failed.", file=sys.stderr)
        return False
    n = sum(len(files) for _, _, files in os.walk(outdir) if any(f.endswith(".java") for f in files))
    print(f"[find-gadget-deser] decompiled {n} .java files into {outdir}", file=sys.stderr)
    return True


def build_db(codeql, src, db, threads=None):
    if os.path.isdir(db) and os.path.exists(os.path.join(db, "codeql-database.yml")):
        print(f"[find-gadget-deser] reusing cached DB {db}", file=sys.stderr)
        return True
    cmd = [codeql, "database", "create", db, "--language=java",
           "--source-root=" + src, "--build-mode=none", "--overwrite"]
    if threads:
        cmd += ["--threads=" + str(threads)]
    r = subprocess.run(cmd)
    if r.returncode != 0:
        print("[find-gadget-deser] ERROR: database create failed.", file=sys.stderr)
        return False
    return True


def gen_query(start_class):
    import re
    tpl = open(TEMPLATE, "r", encoding="utf-8").read()
    if "." in start_class:
        pkg, _, name = start_class.rpartition(".")
        cond = f'this.getDeclaringType().hasQualifiedName("{pkg}", "{name}")'
    else:
        cond = f'this.getDeclaringType().hasName("{start_class}")'
    return re.sub(r"/\*HUNT_START\*/.*?/\*HUNT_END\*/", "/*HUNT_START*/ " + cond + " /*HUNT_END*/", tpl, count=1, flags=re.S)


def analyze(codeql, db, ql, sarif, threads=None):
    cmd = [codeql, "database", "analyze", db, ql,
           "--format=sarif-latest", "--output=" + sarif, "--search-path=" + SEARCH]
    if threads:
        cmd += ["--threads=" + str(threads)]
    return subprocess.run(cmd).returncode == 0


def parse_kind(msg):
    if "deserialization" in msg.lower():
        return "deserialization"
    for s in ("critical", "high", "medium", "low"):
        if "[" + s + "]" in msg.lower():
            return s
    return "info"


def load_results(path):
    if not path or not os.path.exists(path):
        return []
    d = json.load(open(path, "r", encoding="utf-8"))
    return (d.get("runs") or [{}])[0].get("results", [])


def report(sarif, out_md, jar, start_class, full_sarif=None):
    results = load_results(sarif)
    lines = ["# find-gadget-deser report",
             f"_jar: {os.path.basename(jar)} | start-class: {start_class}_\n"]
    lines.append(f"## Reachable from `{start_class}` ({len(results)})\n")
    if not results:
        lines.append("**No dangerous sinks reachable from the start class.**\n")
    else:
        rows = []
        for r in results:
            pl = (r.get("locations", [{}]) or [{}])[0].get("physicalLocation", {})
            uri = pl.get("artifactLocation", {}).get("uri", "?")
            reg = pl.get("region", {})
            loc = f"{uri.split('/')[-1]}:{reg.get('startLine', '?')}"
            msg = (r.get("message", {}).get("text", "") or "").replace("\n", " ")
            rows.append((parse_kind(msg), loc, msg))
        rows.sort(key=lambda x: SEV_ORDER.get(x[0], 9))
        lines.append("| kind | location | chain |")
        lines.append("|---|---|---|")
        for kind, loc, msg in rows:
            m = msg if len(msg) <= 160 else msg[:157] + "..."
            lines.append(f"| {kind} | `{loc}` | {m} |")
        lines.append("")

    if full_sarif:
        full = load_results(full_sarif)
        lines.append(f"## All gadget/sink findings in the jar ({len(full)})\n")
        by = {}
        for r in full:
            rid = r.get("ruleId", "?")
            pl = (r.get("locations", [{}]) or [{}])[0].get("physicalLocation", {})
            uri = pl.get("artifactLocation", {}).get("uri", "?")
            reg = pl.get("region", {})
            loc = f"{uri.split('/')[-1]}:{reg.get('startLine', '?')}"
            msg = (r.get("message", {}).get("text", "") or "").replace("\n", " ")
            by.setdefault(rid, []).append((loc, msg))
        for rid in sorted(by):
            lines.append(f"### {rid} ({len(by[rid])})\n")
            for loc, msg in by[rid]:
                m = msg if len(msg) <= 140 else msg[:137] + "..."
                lines.append(f"- `{loc}` - {m}")
            lines.append("")

    text = "\n".join(lines)
    open(out_md, "w", encoding="utf-8").write(text)
    print(text)
    print(f"\n[find-gadget-deser] report -> {out_md}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description="Scoped deserialization/gadget chain finder for a JAR.")
    ap.add_argument("--jar", required=True, help="path to the .jar to analyse")
    ap.add_argument("--start-class", required=True, help="entry class, e.g. MainWebSpring or com.example.MainWebSpring")
    ap.add_argument("--full", action="store_true", help="also run the full gadget/sink suite (global)")
    ap.add_argument("--cfr", default=None, help="path to cfr.jar (default: auto-download to tools/.cache)")
    ap.add_argument("--codeql", default="codeql", help="path to codeql CLI")
    ap.add_argument("--out", default=None, help="report markdown path")
    ap.add_argument("--threads", type=int, default=None, help="CodeQL --threads=N")
    ap.add_argument("--sarif", default=None, help="also keep the SARIF at this path")
    ap.add_argument("--keep-decompiled", action="store_true", help="keep the decompiled source dir")
    ap.add_argument("--cache-db", default=None, help="reuse a DB dir cached by jar hash (default: tempdir)")
    args = ap.parse_args()

    java = find_java()
    if not java:
        print("[find-gadget-deser] ERROR: no java runtime found (set JAVA_HOME).", file=sys.stderr); sys.exit(1)
    cfr = get_cfr(args.cfr)
    jar_hash = hashlib.sha256(open(args.jar, "rb").read()).hexdigest()[:16]
    db = args.cache_db or os.path.join(tempfile.gettempdir(), "fgd-db-" + jar_hash)
    work = tempfile.mkdtemp(prefix="find-gadget-deser-")
    src = os.path.join(work, "src")
    print(f"[find-gadget-deser] jar={args.jar} start-class={args.start_class} (db cache: {db})", file=sys.stderr)
    if not decompile(java, cfr, args.jar, src):
        sys.exit(1)
    if not build_db(args.codeql, src, db, args.threads):
        sys.exit(1)

    gendir = os.path.join(REPO, "java", "_generated")
    os.makedirs(gendir, exist_ok=True)
    ql = os.path.join(gendir, "ReachableFromStart.ql")
    open(ql, "w", encoding="utf-8").write(gen_query(args.start_class))
    print(f"[find-gadget-deser] generated scoped query -> {ql} (gitignored)", file=sys.stderr)
    print(f"[find-gadget-deser] running scoped reachability query", file=sys.stderr)
    sarif = os.path.join(work, "reachable.sarif")
    if not analyze(args.codeql, db, ql, sarif, args.threads):
        sys.exit(1)
    if args.sarif:
        shutil.copy(sarif, args.sarif)
        print(f"[find-gadget-deser] SARIF kept at {args.sarif}", file=sys.stderr)

    full_sarif = None
    if args.full:
        suite = os.path.join(REPO, "java/suites/java-all.qls")
        full_sarif = os.path.join(work, "full.sarif")
        print(f"[find-gadget-deser] running full suite", file=sys.stderr)
        analyze(args.codeql, db, suite, full_sarif, args.threads)

    out_md = args.out or os.path.join(os.getcwd(), "find-gadget-deser-report.md")
    report(sarif, out_md, args.jar, args.start_class, full_sarif)
    if args.keep_decompiled:
        print(f"[find-gadget-deser] decompiled source kept at {src}", file=sys.stderr)


if __name__ == "__main__":
    main()