#!/usr/bin/env python3
"""
find-gadget-deser.py - scoped deserialization/gadget chain finder for a JAR.

Given a compiled Java archive and an entry/start class, this tool:
  0. for fat/uber jars (Spring Boot BOOT-INF/lib, WAR WEB-INF/lib, ...), also
     extracts and decompiles every *bundled dependency jar* - gadgets almost always
     live in dependencies, so without this they would be invisible,
  1. decompiles the jar(s) to Java source (CFR/Procyon/jadx),
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
  python3 tools/find-gadget-deser.py --jar app.jar --start-class Main --decompiler procyon   # or jadx

Requires:
  - CodeQL CLI on PATH; local packs installed: codeql pack install java/qlpack.yml
  - a Java runtime on PATH (to run the CFR/Procyon decompiler) - or set JAVA_HOME
  - internet on first run to fetch the CFR/Procyon decompiler into tools/.cache
    (or pass --decompiler-jar); jadx is auto-downloaded as a standalone too
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Downloadable decompilers (all auto-fetched to tools/.cache; no manual install).
DECOMPILER_URLS = {
    "cfr": "https://repo1.maven.org/maven2/org/benf/cfr/0.152/cfr-0.152.jar",
    "procyon": "https://github.com/mstrobel/procyon/releases/download/v0.6.0/procyon-decompiler-0.6.0.jar",
}
# jadx ships as a zip (bin/jadx[.bat] + lib/), not a single jar -> handled separately.
JADX_VERSION = "1.5.5"
JADX_URL = f"https://github.com/skylot/jadx/releases/download/v{JADX_VERSION}/jadx-{JADX_VERSION}.zip"
TEMPLATE = os.path.join(REPO, "java", "_generated", "_ReachableFromStartTemplate.ql")
SEARCH = os.path.join(REPO, "java")
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "deserialization": 0, "info": 4}


def find_java():
    p = os.environ.get("JAVA_HOME")
    if p and os.path.exists(os.path.join(p, "bin", "java")):
        return os.path.join(p, "bin", "java")
    from shutil import which
    return which("java")


def get_decompiler_jar(name, override):
    """Path to the CFR/Procyon jar (downloaded+cached under tools/.cache)."""
    if override:
        return override
    cache = os.path.join(REPO, "tools", ".cache")
    os.makedirs(cache, exist_ok=True)
    jarpath = os.path.join(cache, name + ".jar")
    if not os.path.exists(jarpath):
        print(f"[find-gadget-deser] downloading {name} decompiler -> {jarpath}", file=sys.stderr)
        urllib.request.urlretrieve(DECOMPILER_URLS[name], jarpath)
    return jarpath


def get_jadx():
    """Return a launcher for a self-contained standalone jadx, downloading the
    release zip into tools/.cache/jadx on first use. We deliberately do NOT reuse a
    `jadx` found on PATH: a user's PATH `jadx` is frequently a jadx-GUI shim that
    ignores CLI decompile args (produces zero files). Pass --decompiler-jar to
    force a specific jadx launcher."""
    cache = os.path.join(REPO, "tools", ".cache")
    jadx_dir = os.path.join(cache, "jadx")
    launcher = os.path.join(jadx_dir, "bin", "jadx.bat" if os.name == "nt" else "jadx")
    if not os.path.exists(launcher):
        os.makedirs(jadx_dir, exist_ok=True)
        zpath = os.path.join(cache, f"jadx-{JADX_VERSION}.zip")
        if not os.path.exists(zpath):
            print(f"[find-gadget-deser] downloading jadx {JADX_VERSION} -> {zpath}", file=sys.stderr)
            urllib.request.urlretrieve(JADX_URL, zpath)
        print(f"[find-gadget-deser] extracting standalone jadx -> {jadx_dir}", file=sys.stderr)
        with zipfile.ZipFile(zpath) as z:
            z.extractall(jadx_dir)
        if os.name != "nt":
            for b in ("jadx", "jadx-gui"):
                p = os.path.join(jadx_dir, "bin", b)
                if os.path.exists(p):
                    try:
                        os.chmod(p, 0o755)
                    except OSError:
                        pass
    return launcher


def collect_jars(primary_jar, workdir, include_nested, cap=2000):
    """Return a list of (jarpath, label) to decompile: the primary jar plus any
    *.jar bundled inside it (Spring Boot `BOOT-INF/lib/`, WAR `WEB-INF/lib/`, or
    anywhere) - recursively. Nested jars are extracted under `workdir`. Without
    this, decompilers only see the outer jar's own classes and miss every gadget
    that lives in a bundled dependency."""
    jars = [(primary_jar, "root")]
    if not include_nested:
        return jars
    extract_root = os.path.join(workdir, "nested")
    n = 0
    queue = [primary_jar]
    while queue and n < cap:
        jar = queue.pop()
        try:
            zf = zipfile.ZipFile(jar)
        except (zipfile.BadZipFile, OSError):
            continue
        with zf:
            for name in zf.namelist():
                if not name.lower().endswith(".jar"):
                    continue
                os.makedirs(extract_root, exist_ok=True)
                target = os.path.join(extract_root, f"{n:04d}_{os.path.basename(name)}")
                try:
                    with zf.open(name) as s, open(target, "wb") as d:
                        shutil.copyfileobj(s, d)
                except OSError:
                    continue
                jars.append((target, os.path.splitext(os.path.basename(name))[0]))
                queue.append(target)
                n += 1
                if n >= cap:
                    print(f"[find-gadget-deser] WARNING: nested-jar cap {cap} reached; some deps skipped", file=sys.stderr)
                    break
    return jars


def decompile(java, decompiler, decompiler_jar, jar, outdir):
    """Decompile `jar` into `outdir` with the chosen decompiler; return the actual
    source root (a subdir for jadx) or None on failure."""
    if os.path.isdir(outdir):
        shutil.rmtree(outdir)
    if decompiler == "cfr":
        cmd = [java, "-jar", decompiler_jar, jar, "--outputdir", outdir]
    elif decompiler == "procyon":
        cmd = [java, "-jar", decompiler_jar, "-o", outdir, jar]
    elif decompiler == "jadx":
        jadx = decompiler_jar or "jadx"   # standalone launcher from get_jadx() (or --decompiler-jar)
        cmd = [jadx, "--no-res", "-d", outdir, jar]
    else:
        print(f"[find-gadget-deser] ERROR: unknown decompiler {decompiler!r}.", file=sys.stderr)
        return None
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout); print(r.stderr, file=sys.stderr)
        print(f"[find-gadget-deser] ERROR: {decompiler} decompilation failed"
              + (" (is jadx on PATH?)" if decompiler == "jadx" else "") + ".", file=sys.stderr)
        return None
    # jadx writes decompiled .java under <outdir>/sources
    srcroot = outdir
    if decompiler == "jadx" and os.path.isdir(os.path.join(outdir, "sources")):
        srcroot = os.path.join(outdir, "sources")
    n = sum(len(files) for _, _, files in os.walk(srcroot) if any(f.endswith(".java") for f in files))
    print(f"[find-gadget-deser] {decompiler} decompiled {n} .java files into {srcroot}", file=sys.stderr)
    return srcroot


def build_db(codeql, src, db, threads=None):
    if os.path.isdir(db) and os.path.exists(os.path.join(db, "codeql-database.yml")):
        print(f"[find-gadget-deser] reusing cached DB {db}", file=sys.stderr)
        return True
    cmd = [codeql, "database", "create", db, "--language=java",
           "--source-root=" + src, "--build-mode=none", "--overwrite"]
    if threads is not None:
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
    if threads is not None:
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
    ap.add_argument("--decompiler", choices=["cfr", "procyon", "jadx"], default="cfr",
                    help="decompiler: cfr (default) / procyon / jadx - ALL auto-downloaded to tools/.cache "
                         "(jadx as a standalone zip; a jadx already on PATH is reused). "
                         "Try procyon or jadx when CFR emits code CodeQL cannot parse on large/obfuscated jars.")
    ap.add_argument("--decompiler-jar", default=None,
                    help="override path to the cfr/procyon jar (default: auto-download to tools/.cache)")
    ap.add_argument("--cfr", default=None, help="[deprecated alias for --decompiler-jar when --decompiler=cfr]")
    ap.add_argument("--codeql", default="codeql", help="path to codeql CLI")
    ap.add_argument("--out", default=None, help="report markdown path")
    ap.add_argument("--threads", type=int, default=0,
                    help="CodeQL --threads=N for create+analyze (default 0 = one per core)")
    ap.add_argument("--sarif", default=None,
                    help="SARIF output path (default: alongside the report as <out>.sarif; also fed to gen-poc.py)")
    ap.add_argument("--keep-decompiled", action="store_true", help="keep the decompiled source dir")
    ap.add_argument("--cache-db", default=None, help="reuse a DB dir cached by jar hash (default: tempdir)")
    ap.add_argument("--skip-nested-jars", action="store_true",
                    help="do NOT descend into bundled dependency jars (BOOT-INF/lib, WEB-INF/lib, ...); "
                         "by default nested jars ARE decompiled so gadgets in dependencies are found")
    args = ap.parse_args()

    java = find_java()
    if not java:
        print("[find-gadget-deser] ERROR: no java runtime found (set JAVA_HOME).", file=sys.stderr); sys.exit(1)
    jar_hash = hashlib.sha256(open(args.jar, "rb").read()).hexdigest()[:16]
    db = args.cache_db or os.path.join(tempfile.gettempdir(), "fgd-db-" + jar_hash)
    db_cached = os.path.isdir(db) and os.path.exists(os.path.join(db, "codeql-database.yml"))
    work = tempfile.mkdtemp(prefix="find-gadget-deser-")
    src = os.path.join(work, "src")
    srcroot = src
    print(f"[find-gadget-deser] jar={args.jar} start-class={args.start_class} decompiler={args.decompiler} (db cache: {db})", file=sys.stderr)
    # Decompilation only feeds the DB build; skip it entirely when the DB is already
    # cached for this jar sha256 (unless --keep-decompiled asks for the source).
    if db_cached and not args.keep_decompiled:
        print(f"[find-gadget-deser] DB cached for jar sha256={jar_hash}; skipping decompile+build", file=sys.stderr)
    else:
        decompiler_jar = None
        if args.decompiler in ("cfr", "procyon"):
            override = args.decompiler_jar or (args.cfr if args.decompiler == "cfr" else None)
            decompiler_jar = get_decompiler_jar(args.decompiler, override)
        elif args.decompiler == "jadx":
            decompiler_jar = args.decompiler_jar or get_jadx()
        # Fat/uber jars (Spring Boot BOOT-INF/lib, WAR WEB-INF/lib) bundle their
        # dependencies as nested jars; gadgets almost always live in those deps, so
        # decompile every nested jar too (not just the outer one) into one src tree.
        jars = collect_jars(args.jar, work, not args.skip_nested_jars)
        nested = len(jars) - 1
        if nested > 0:
            print(f"[find-gadget-deser] fat/uber jar: found {nested} nested dependency jar(s); "
                  f"decompiling all (use --skip-nested-jars to skip)", file=sys.stderr)
        ok = 0
        for idx, (jarpath, label) in enumerate(jars):
            if decompile(java, args.decompiler, decompiler_jar, jarpath, os.path.join(src, f"{idx:04d}_{label}")) is not None:
                ok += 1
        if ok == 0:
            print("[find-gadget-deser] ERROR: nothing decompiled.", file=sys.stderr)
            sys.exit(1)
        srcroot = src
    if not build_db(args.codeql, srcroot, db, args.threads):
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

    full_sarif = None
    if args.full:
        suite = os.path.join(REPO, "java/suites/java-all.qls")
        full_sarif = os.path.join(work, "full.sarif")
        print(f"[find-gadget-deser] running full suite", file=sys.stderr)
        analyze(args.codeql, db, suite, full_sarif, args.threads)

    out_md = args.out or os.path.join(os.getcwd(), "find-gadget-deser-report.md")
    # Always keep the scoped SARIF (for VS Code / GitHub code scanning and gen-poc.py).
    sarif_out = args.sarif or os.path.splitext(out_md)[0] + ".sarif"
    shutil.copy(sarif, sarif_out)
    print(f"[find-gadget-deser] SARIF -> {sarif_out}  (feed to: python3 tools/gen-poc.py --sarif {sarif_out})", file=sys.stderr)
    report(sarif, out_md, args.jar, args.start_class, full_sarif)
    if args.keep_decompiled:
        print(f"[find-gadget-deser] decompiled source kept at {src}", file=sys.stderr)


if __name__ == "__main__":
    main()