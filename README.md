# java/python deserialization — CodeQL query packs (daily gadget hunting)

Curated [CodeQL](https://codeql.github.com/) query packs for finding
**deserialization sinks**, **source-to-sink chains** and **ysoserial-style
gadget chains** in **Java** and **Python** codebases. Comes with a buildless
hunting CLI so a researcher can point it at any Java source tree and get a
ranked gadget report without Maven/Gradle/deps.

- Java pack: `hypnguyen1209/java-deserialization` (depends on `codeql/java-all`)
- Python pack: `hypnguyen1209/python-deserialization` (depends on `codeql/python-all`)
- **14 queries** (12 Java + 2 Python), **13/13 tests pass**, validated against
  real databases including `frohoff/ysoserial` itself.

> ⚠️ **Authorization** — Only run these queries against code you own or are
> explicitly authorized to assess. The repo also ships vulnerable **test**
> fixtures; never deploy them.

---

## Daily hunting (start here)

```bash
codeql pack install java/qlpack.yml python/qlpack.yml

# Point it at ANY Java source (buildless — no Maven/Gradle/deps needed):
python tools/hunt.py /path/to/target --mode full   --out report.md   # sinks + chains + gadgets
python tools/hunt.py /path/to/target --mode gadgets --out gadgets.md # ysoserial-style gadget queries
python tools/hunt.py /path/to/target --lang python                    # Python sinks/chains
python tools/hunt.py /path/to/target --command "mvn -B compile -q"   # real build if you want stronger types
```

`tools/hunt.py` builds a CodeQL database (`--build-mode=none` for Java by
default), runs the chosen suite, and writes a Markdown report grouped by rule
and sorted by severity (`[critical]` > `[high]` > `[medium]`).

**Validated on `frohoff/ysoserial`**: 48 findings — 1 `readObject -> exec`
gadget chain, 45 RCE action calls (`Class.forName`, `Method.invoke`,
`ClassLoader.loadClass`, `URL.openConnection`, `Runtime.exec`) across the
payloads/exploit code, 1 gadget entry, 1 novel gadget. See
[`examples/ysoserial-hunt-report.md`](./examples/ysoserial-hunt-report.md) and
[`docs/hunting-guide.md`](./docs/hunting-guide.md) for the daily workflow.

---

## Packs

| Pack | Registry name | Depends on |
|---|---|---|
| Java | `hypnguyen1209/java-deserialization` | `codeql/java-all` |
| Python | `hypnguyen1209/python-deserialization` | `codeql/python-all` |

## Repository layout

```
.
├── java/deserialization/        # sink + chain queries (reuse codeql/java-all model)
│   ├── DeserializationSinks.ql          # every deserialization sink (problem)
│   ├── UnsafeDeserialization.ql          # remote source -> sink (path)
│   ├── UnsafeDeserializationType.ql      # remote -> polymorphic type descriptor (path)
│   ├── UnsafeDeserializationRmi.ql       # RMI: bind a remote object with a complex method (path)
│   ├── UnsafeSpringExporter.ql          # Spring remoting @Bean exporter that deserializes (problem)
│   ├── DubboDeserialization.ql           # Apache Dubbo Codec2 -> ObjectInput chain (path)
│   ├── DeserializationSinkModel.qll      # generic sink model
│   ├── DubboDeserializationModel.qll      # Dubbo source/sink + taint steps
│   └── SpringExporterModel.qll
├── java/gadgets/               # ysoserial-style gadget detection
│   ├── GadgetEntryPoints.ql            # Serializable readObject/readResolve/readExternal (problem)
│   ├── GadgetActionCalls.ql            # RCE primitives: exec/invoke/lookup/loadClass/eval/... (problem)
│   ├── DeserializationGadgetChain.ql    # entry -> action call-graph reachability (problem)
│   ├── GadgetDispatchChain.ql          # Serializable link method -> action (dispatch gadget) (problem)
│   ├── NovelGadgetCandidates.ql        # entry/dispatch -> action, NOT in ysoserial catalog (problem)
│   ├── KnownYsoserialGadgetClasses.ql  # class from the ysoserial catalog present in source (problem)
│   └── GadgetModel.qll                 # entry/link/action/catalog model + reachability
├── python/deserialization/      # Python sinks + chains (reuse codeql/python-all model)
│   ├── DeserializationSinks.ql
│   ├── UnsafeDeserialization.ql
│   └── DeserializationSinkModel.qll
├── java/suites/  python/suites/ # java-deserialization / java-gadgets / java-all / python-deserialization
├── tests/                       # 13 vulnerable+safe fixtures with .expected files
├── tools/hunt.py                # buildless hunting CLI -> ranked Markdown report
├── examples/                    # runnable demo targets + run-debug scripts + ysoserial hunt report
├── docs/                        # hunting-guide, deep-debug, references, extending
├── codeql-workspace.yml
└── .github/workflows/           # check-queries (compile+test), publish (GHCR)
```

## Queries

### Java — sinks & chains (CWE-502, reuse `codeql/java-all`)
| Query | `@id` | Kind | What it finds |
|---|---|---|---|
| Deserialization sink | `java/deserialization/sink` | problem | every deserialization sink call (gadget triage) |
| Unsafe deserialization chain | `java/deserialization/unsafe-chain` | path | remote/user source -> deserialization sink |
| Unsafe polymorphic type | `java/deserialization/unsafe-type` | path | remote -> polymorphic type descriptor (Jackson/Jodd/Gson) |
| Unsafe RMI deserialization | `java/deserialization/rmi` | path | RMI bind of a remote object with a complex-typed method |
| Spring remote exporter | `java/deserialization/spring-exporter` | problem | Spring remoting @Bean exporter that deserializes request bodies |
| Apache Dubbo chain | `java/deserialization/dubbo-chain` | path | Dubbo `Codec2.decodeBody` -> `ObjectInput.readXXX` (CVE-2020-11995 style) |

Generic sinks: `ObjectInputStream.readObject/readUnshared`, `XMLDecoder`,
XStream, Kryo, SnakeYAML, Jackson polymorphic, Hessian/Burlap, Jodd, Gson,
Fastjson, JsonIo, Jabsorb, `ObjectMessage.getObject()` — all from the official
`UnsafeDeserializationSink` model; recognized-safe variants (ValidatingObjectInputStream,
SerialKiller, XStream/Kryo whitelist, SnakeYAML `SafeConstructor`, Jackson type
validator) are excluded.

### Java — ysoserial-style gadgets (CWE-502, modelled on `frohoff/ysoserial`)
| Query | `@id` | Kind | What it finds |
|---|---|---|---|
| Gadget entry point | `java/deserialization/gadget-entry` | problem | `Serializable` `readObject`/`readResolve`/`readExternal`/`readObjectNoData` (chain start) |
| Gadget action call | `java/deserialization/gadget-action` | problem | RCE primitives (`Runtime.exec`, `Method.invoke`, `Class.forName`, `ClassLoader.loadClass`, `ScriptEngine.eval`, JNDI `lookup`, `Templates.newTransformer`, `URL.openConnection`, ...) |
| Gadget chain (entry -> action) | `java/deserialization/gadget-chain` | problem | a serializable callback transitively reaching an RCE action via the call graph |
| Gadget dispatch | `java/deserialization/gadget-dispatch` | problem | a serializable "link" method (`InvocationHandler.invoke`, `Comparator.compare`, `Map.get/put`, `equals/hashCode/toString`) reaching an action — the ysoserial "middle" gadgets |
| Novel gadget candidate | `java/deserialization/novel-gadget` | problem | entry/dispatch -> action, **excluding** the known ysoserial catalog — candidate NEW gadgets to investigate |
| Known ysoserial gadget class | `java/deserialization/known-gadget-class` | problem | a source class matching the ysoserial catalog (`InvokerTransformer`, `TemplatesImpl`, `BeanComparator`, `MethodClosure`, `JtaTransactionManager`, ...) |

### Python (CWE-502, reuse `codeql/python-all`)
| Query | `@id` | Kind | What it finds |
|---|---|---|---|
| Deserialization sink | `python/deserialization/sink` | problem | every insecure decoding (pickle/cPickle/marshal/yaml/shelve/dill/jsonpickle/pandas.read_pickle) |
| Unsafe deserialization chain | `python/deserialization/unsafe-chain` | path | remote/user source -> insecure decoding sink |

## Quickstart (manual, without hunt.py)

```bash
codeql database create my-java-db --language=java --source-root=src --build-mode=none
codeql database create my-py-db   --language=python --source-root=.

codeql database analyze my-java-db java/suites/java-all.qls --search-path=java --format=sarif-latest --output=java.sarif
codeql database analyze my-py-db   python/suites/python-deserialization.qls --search-path=python --format=sarif-latest --output=py.sarif
```

## Using as a custom query suite in GitHub Advanced Security

```yaml
# .github/codeql/codeql-config.yml
packs:
  - source: "hypnguyen1209/java-deserialization"
  - source: "hypnguyen1209/python-deserialization"
```

## Tests & validation

```bash
codeql test run tests/java tests/python      # 13/13 pass
bash examples/run-debug.sh                    # examples/run-debug.ps1 on Windows — builds real DBs, parity vs official
```

- **13 unit tests** (11 Java + 2 Python) with vulnerable + safe fixtures and
  committed `.expected` files.
- **Deep-debug on real DBs** ([`docs/deep-debug.md`](./docs/deep-debug.md)):
  Java 8 sinks across 8 frameworks + 6 recognized-safe variants; parity with
  official `java/unsafe-deserialization` (same 8 results); Python 10 sinks +
  safe YAML excluded; gadget queries give 0 false positives on generic code.
- **Real run on `frohoff/ysoserial`** ([`examples/ysoserial-hunt-report.md`](./examples/ysoserial-hunt-report.md)):
  finds the `readObject -> exec` gadget chain and the real RCE actions.

## Extending

- Add a sink for a custom framework: model source/sink + extra taint steps —
  see `DubboDeserializationModel.qll` and [`docs/extending.md`](./docs/extending.md).
- Add a known gadget class: append to `isKnownYsoserialGadgetClass` in
  `java/gadgets/GadgetModel.qll`.
- Regenerate expectations with `codeql test run --learn <dir>` (review by hand).

## Acknowledgements & references

See [`docs/references.md`](./docs/references.md). In particular: generic
Java/Python models reuse GitHub's `codeql/java-all` + `codeql/python-all`
(Apache-2.0); the Dubbo chain adapts `pwntester/codeql_grehack_workshop` (MIT);
the RMI query adapts GitHub's experimental `java/unsafe-deserialization-rmi`;
the Spring exporter adapts `GitHubSecurityLab/CodeQL-Community-Packs` (MIT); the
gadget model/catalog are derived from `frohoff/ysoserial` (MIT).

## License

MIT — see [LICENSE](./LICENSE). The library packs it depends on
(`codeql/java-all`, `codeql/python-all`) are licensed by GitHub under their own
terms (https://github.com/github/codeql).
