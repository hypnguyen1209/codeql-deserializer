# codeql-deserializer

> CodeQL query packs + CLI tools for hunting **deserialization sinks, source-to-sink chains and ysoserial-style gadget chains** in Java & Python.

[![CI](https://github.com/hypnguyen1209/codeql-deserializer/actions/workflows/check-queries.yml/badge.svg)](https://github.com/hypnguyen1209/codeql-deserializer/actions/workflows/check-queries.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
![Queries](https://img.shields.io/badge/queries-16-blue)
![Tests](https://img.shields.io/badge/tests-15%2F15-brightgreen)

## What this is

Two [CodeQL](https://codeql.github.com/) query packs (`hypnguyen1209/java-deserialization`,
`hypnguyen1209/python-deserialization`) plus two hunting CLIs that turn CodeQL into a
daily driver for deserialization research. Given Java or Python source (or a compiled
`.jar`), it tells you **where untrusted data is deserialized** and **which gadget chains
could weaponise it** — without you writing any CodeQL.

- **16 queries** (14 Java + 2 Python), **15/15 tests pass**, CI-verified on Ubuntu.
- Reuses GitHub's official `codeql/java-all` + `codeql/python-all` models (no hand-rolled
  sink logic that drifts); adds framework-specific chains (Dubbo, RMI, Spring) and a
  ysoserial-style gadget model.
- Validated on real databases, including `frohoff/ysoserial` itself.

> ⚠️ **Authorization** — run only against code you own or are authorized to assess.
> The repo ships vulnerable **test** fixtures; never deploy them.

## How it works (mental model)

A deserialization exploit needs three things. The pack finds each:

```
   SOURCE  ──(flow)──▶  SINK  ──(call graph)──▶  ACTION
   remote/user data   readObject()/pickle    Runtime.exec / Method.invoke / JNDI.lookup
                      ObjectInputStream       Templates.newTransformer / ClassLoader.loadClass ...
```

| Concept | Question it answers | Java query `@id` |
|---|---|---|
| **Sink** | Where is untrusted data deserialized? | `java/deserialization/sink`, `unsafe-chain` |
| **Chain** | Does a remote source reach the sink? | `java/deserialization/unsafe-chain` (path) |
| **Gadget entry** | Which `Serializable.readObject`/`readResolve` run on attacker data? | `java/deserialization/gadget-entry` |
| **Gadget action** | Which RCE primitive could a chain end in? | `java/deserialization/gadget-action` |
| **Gadget chain** | Does a gadget entry reach an RCE action (call graph)? | `java/deserialization/gadget-chain` |
| **Gadget dispatch** | Which "middle" gadget (InvocationHandler/Comparator/Map) reaches action? | `java/deserialization/gadget-dispatch` |
| **Novel gadget** | Entry/dispatch → action, **not** in the known ysoserial catalog? | `java/deserialization/novel-gadget` |
| **Known gadget class** | Is a ysoserial catalog class present in source? | `java/deserialization/known-gadget-class` |

## Prerequisites

| Need | For | Install |
|---|---|---|
| **CodeQL CLI** ≥ 2.20 | all queries & tools | [releases](https://github.com/github/codeql-cli-binaries/releases) → `codeql` on PATH |
| **Python 3** | `tools/hunt.py`, `tools/find-gadget-deser.py` | on PATH |
| **Java 17+** | `find-gadget-deser.py` (runs CFR) & Java DBs | on PATH or `JAVA_HOME` |
| **Decompiler** (CFR/Procyon/jadx) | `find-gadget-deser.py` only | **all auto-downloaded** to `tools/.cache` (CFR/Procyon jars, jadx standalone zip); or `--decompiler-jar <path>` |
| **internet (1st run)** | `codeql pack install` + first decompiler fetch | pulls `codeql/java-all`, `codeql/python-all` from GHCR + the chosen decompiler (Maven Central / GitHub releases) |

The packs' only real dependency is the official library packs (declared in each
`qlpack.yml`): `hypnguyen1209/java-deserialization` → `codeql/java-all`,
`hypnguyen1209/python-deserialization` → `codeql/python-all`. Everything else
(tests, examples, tools) is self-contained in this repo.

## Quick start

### 1 · Install the packs (one time)

```bash
git clone https://github.com/hypnguyen1209/codeql-deserializer
cd codeql-deserializer
codeql pack install java/qlpack.yml python/qlpack.yml
```

### 2 · Hunt

Pick the mode that matches what you have:

**A — Java source tree** (`tools/hunt.py`, buildless — no Maven/Gradle/deps needed):

```bash
python tools/hunt.py path/to/java-src --mode full   --out report.md   # sinks + chains + gadgets
python tools/hunt.py path/to/java-src --mode gadgets --out gadgets.md # ysoserial gadget queries only
# optional real build for stronger type info:
python tools/hunt.py path/to/java-src --command "mvn -B compile -q"
```

**B — Compiled JAR + entry class** (`tools/find-gadget-deser.py`):
decompiles the jar (CFR by default; `--decompiler procyon|jadx` — all three auto-downloaded to `tools/.cache`, no manual install — for jars CFR chokes on) → buildless DB → reports chains **from your start class**
to any dangerous sink (deserialize **or** RCE action), via the call graph. For
**fat/uber jars** (Spring Boot `BOOT-INF/lib/*.jar`, WAR `WEB-INF/lib/*.jar`, …) it
also extracts and decompiles every **bundled dependency jar** — gadgets almost always
live in dependencies, so without this they'd be invisible (`--skip-nested-jars` to opt out):

```bash
python3 tools/find-gadget-deser.py --jar app.jar --start-class MainWebSpring          # scoped chains
python3 tools/find-gadget-deser.py --jar app.jar --start-class com.example.MainWebSpring --full
python3 tools/find-gadget-deser.py --jar springboot-fat.jar --start-class com.example.Application --full  # scans BOOT-INF/lib gadgets
```

**C — Python source:**

```bash
python tools/hunt.py path/to/py-src --lang python --mode full --out report.md
```



### PoC skeleton + benchmark

- `tools/gen-poc.py --sarif <find-gadget-deser.sarif>` lists the chain hits; add `--index N --yes-i-have-authorization -o PoC.java` to emit a minimal Java serialize->deserialize harness skeleton for that hit. It is **optional**, prints an authorization warning, and refuses to write without the ack flag; the skeleton is **non-armed** (`buildGadget()` throws — you construct the real gadget graph and validate yourself).
- `benchmark/bench.py` — recall/precision benchmark on known chains (commons-collections-style, commons-beanutils `BeanComparator`, + a safe control). Run: `python3 benchmark/bench.py` (needs `javac` on PATH).

Both hunting tools print a ranked Markdown report (grouped by rule, sorted `[critical]` >
`[high]` > `[medium]`) and write it to `--out`.

### 3 · Read the report

- **`Reachable from <start-class>`** = scoped chains from your entry (B) / per-rule
  findings (A,C).
- Triage order: `novel-gadget` + `gadget-dispatch` first (candidate new gadgets),
  then `gadget-chain`/`unsafe-chain` (confirmed sinks), then `known-gadget-class`
  (catalog hits that make a sink exploitable).

See [`docs/hunting-guide.md`](./docs/hunting-guide.md) for the full daily workflow.

## Query reference

### Java — sinks & chains (reuse `codeql/java-all`)
| `@id` | Kind | Finds |
|---|---|---|
| `java/deserialization/sink` | problem | every deserialization sink call (triage) |
| `java/deserialization/unsafe-chain` | path | remote source → sink |
| `java/deserialization/unsafe-type` | path | remote → polymorphic type descriptor (Jackson/Jodd/Gson) |
| `java/deserialization/rmi` | path | RMI bind of a remote object with a complex-typed method |
| `java/deserialization/spring-exporter` | problem | Spring remoting `@Bean` exporter that deserializes request bodies |
| `java/deserialization/dubbo-chain` | path | Dubbo `Codec2.decodeBody` → `ObjectInput.readXXX` (CVE-2020-11995 style) |

Covered sinks: `ObjectInputStream.readObject/readUnshared`, `XMLDecoder`, XStream,
Kryo (incl. `readClassAndObject` + pool variants), SnakeYAML, Jackson polymorphic,
Hessian/Burlap + `Hessian2Input`, Jodd, Gson, Fastjson, JsonIo, Jabsorb,
`ObjectMessage.getObject()`, and the RMI/JMX-remote `MarshalledObject.get()` /
`javax.management.remote.rmi.RMIConnection` primitives. Recognized-safe variants are
excluded: `ValidatingObjectInputStream`, `SerialKiller`, XStream/Kryo whitelist,
SnakeYAML `SafeConstructor`, Jackson type validator.

### Java — ysoserial-style gadgets (modelled on `frohoff/ysoserial`)
| `@id` | Kind | Finds |
|---|---|---|
| `java/deserialization/gadget-entry` | problem | `Serializable` `readObject`/`readResolve`/`readExternal`/`readObjectNoData` (chain start) |
| `java/deserialization/gadget-action` | problem | RCE primitives: `Runtime.exec`, `Method.invoke`, `Class.forName`, `ClassLoader.loadClass`, `ScriptEngine.eval`, JNDI `lookup`, `Templates.newTransformer`, `URL.openConnection`, JMX `MBeanServer.invoke`, Groovy/JShell/OGNL/MVEL/SpEL/Velocity/Freemarker eval, javassist `ProxyFactory`, … |
| java/deserialization/gadget-chain | problem | entry → action via the call graph (endpoints only) |
| java/deserialization/gadget-chain-path | **path** | entry to action as an explorable path (`readObject -> ... -> hashCode -> invoke -> exec`) in SARIF/VS Code, over the call graph + dispatch edges (depth-capped) |
| java/deserialization/gadget-chain-steps | problem | same, but renders the intermediate call path  -> b -> ... -> exec (≤4 hops) |
| `java/deserialization/gadget-dispatch` | problem | serializable "link" method (`InvocationHandler.invoke`, `Comparator.compare`, `Map.get/put`, `equals/hashCode/toString`) → action |
| `java/deserialization/novel-gadget` | problem | entry/dispatch → action, **not** in the ysoserial catalog → candidate new gadget |
| `java/deserialization/known-gadget-class` | problem | a class matching the ysoserial catalog (`InvokerTransformer`, `TemplatesImpl`, `BeanComparator`, `MethodClosure`, `JtaTransactionManager`, …) |

### Python (reuse `codeql/python-all`)
| `@id` | Kind | Finds |
|---|---|---|
| `python/deserialization/sink` | problem | every insecure decoding (pickle/cPickle/marshal/yaml/shelve/dill/jsonpickle/pandas.read_pickle) |
| `python/deserialization/unsafe-chain` | path | remote source → insecure decoding sink |

## Repository layout

```
java/deserialization/   sink + chain queries + models  (6 .ql, reuse codeql/java-all)
java/gadgets/            ysoserial-style gadget queries + model (6 .ql + HuntReachabilityModel.qll)
java/suites/             java-deserialization.qls / java-gadgets.qls / java-all.qls
python/deserialization/  sink + chain queries (2 .ql)
python/suites/            python-deserialization.qls
tests/                   13 vulnerable+safe fixtures with committed .expected
tools/hunt.py            buildless source-tree hunting CLI → ranked report
tools/find-gadget-deser.py  JAR + start-class scoped gadget finder (CFR + buildless)
examples/                runnable demo targets, run-debug scripts, sample hunt reports
docs/                    hunting-guide · deep-debug · references · extending
codeql-workspace.yml     registers the 4 local packs
.github/workflows/       check-queries (compile+test, green) · publish (GHCR on tag)
```

## Validation

```bash
codeql test run tests/java tests/python            # 13/13 unit tests
bash examples/run-debug.sh                          # build real DBs, parity vs official query
```

- **15 unit tests** (13 Java + 2 Python): vulnerable fixtures flagged, safe variants not.
- **Deep-debug** ([`docs/deep-debug.md`](./docs/deep-debug.md)): Java 8 sinks across 8
  frameworks + 6 safe variants excluded; **parity** with GitHub's official
  `java/unsafe-deserialization` (same 8 results); Python 10 sinks + safe YAML excluded;
  gadget queries produce **0 false positives** on generic code.
- **Real run on `frohoff/ysoserial`** ([`examples/ysoserial-hunt-report.md`](./examples/ysoserial-hunt-report.md)):
  finds the `readObject → exec` gadget chain and 45 RCE action calls.
- **Scoped JAR run** ([`examples/find-gadget-deser-complex-report.md`](./examples/find-gadget-deser-complex-report.md)):
  from a Spring-style main class, finds 7 reachable dangerous sinks and correctly
  excludes an unreachable admin-backdoor JNDI sink.

## Manual usage (without the CLIs)

```bash
codeql database create my-java-db --language=java   --source-root=src --build-mode=none
codeql database create my-py-db   --language=python --source-root=.

codeql database analyze my-java-db java/suites/java-all.qls          --search-path=java   --format=sarif-latest --output=java.sarif
codeql database analyze my-py-db   python/suites/python-deserialization.qls --search-path=python --format=sarif-latest --output=py.sarif
```

## GitHub Advanced Security (code scanning)

```yaml
# .github/codeql/codeql-config.yml
packs:
  - source: "hypnguyen1209/java-deserialization"
  - source: "hypnguyen1209/python-deserialization"
```

## Extending

- **New sink for a custom framework**: model source/sink + extra taint steps —
  see `java/deserialization/DubboDeserializationModel.qll` and
  [`docs/extending.md`](./docs/extending.md).
- **New known gadget class**: append to `isKnownYsoserialGadgetClass` in
  `java/gadgets/GadgetModel.qll`.
- **Regenerate expectations**: `codeql test run --learn tests/java` (review the diff).

## Publishing packs to GHCR

Tag a release (`vX.Y.Z`) and push the tag; `.github/workflows/publish.yml` publishes
both packs to `ghcr.io/hypnguyen1209/*` (needs `packages: write`, default `GITHUB_TOKEN` suffices):

```bash
git tag v0.0.7 && git push origin v0.0.7
```

## Acknowledgements

See [`docs/references.md`](./docs/references.md). In short — generic Java/Python models
reuse GitHub's `codeql/java-all` + `codeql/python-all` (Apache-2.0); the Dubbo chain
adapts `pwntester/codeql_grehack_workshop` (MIT); the RMI query adapts GitHub's
experimental `java/unsafe-deserialization-rmi` (Apache-2.0); the Spring exporter adapts
`GitHubSecurityLab/CodeQL-Community-Packs` (MIT); the gadget model/catalog are derived
from `frohoff/ysoserial` (MIT).

## License

MIT — see [LICENSE](./LICENSE). The library packs it depends on
(`codeql/java-all`, `codeql/python-all`) are licensed by GitHub under their own terms
(https://github.com/github/codeql).