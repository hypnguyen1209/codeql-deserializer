# java/python deserialization — CodeQL query packs

Curated [CodeQL](https://codeql.github.com/) query packs for finding
**deserialization sinks** and **source-to-sink chains** in **Java** and
**Python** codebases. Published to the GitHub Container Registry as
`hypnguyen1209/java-deserialization` and `hypnguyen1209/python-deserialization`.

The generic Java/Python queries reuse GitHub's official CWE-502 models
(`codeql/java-all`, `codeql/python-all`). On top of that, the pack adds
**framework-specific deserialization chain** queries — an Apache Dubbo chain
(adapted from the GreHack 2021 workshop) and an RMI "remotely callable method"
query — as concrete, tested examples of how to extend the pack for custom
frameworks. See [Acknowledgements & references](#acknowledgements--references).

> ⚠️ **Authorization** — Only run these queries against code you own or are
> explicitly authorized to assess. The pack also ships vulnerable **test**
> fixtures; never deploy them.

---

## Packs

| Pack | Registry name | Depends on |
|---|---|---|
| Java | `hypnguyen1209/java-deserialization` | `codeql/java-all` |
| Python | `hypnguyen1209/python-deserialization` | `codeql/python-all` |

## Repository layout

```
.
├── java/deserialization/
│   ├── DeserializationSinks.ql          # every deserialization sink (problem)        [official model]
│   ├── UnsafeDeserialization.ql          # remote source -> deserialization sink (path) [official model]
│   ├── UnsafeDeserializationType.ql      # remote -> polymorphic type descriptor (path) [official model]
│   ├── UnsafeDeserializationRmi.ql       # RMI: bind a remote object with a complex-typed method (path)
│   ├── DubboDeserialization.ql            # Apache Dubbo Codec2.decodeBody -> ObjectInput.readXXX (path)
│   ├── DeserializationSinkModel.qll       # generic sink model (re-exports codeql/java-all)
│   └── DubboDeserializationModel.qll       # Dubbo-specific source/sink + taint steps
├── python/deserialization/
│   ├── DeserializationSinks.ql            # every insecure decoding (problem)
│   ├── UnsafeDeserialization.ql          # remote source -> insecure decoding (path)
│   └── DeserializationSinkModel.qll
├── tests/{java,python}/                   # vulnerable + safe fixtures with .expected files
├── .github/workflows/                     # check-queries (compile+test), publish (GHCR)
├── codeql-workspace.yml
└── docs/{extending.md,references.md}
```

## Queries

### Java (CWE-502)
| Query | `@id` | Kind | What it finds |
|---|---|---|---|
| Deserialization sink | `java/deserialization/sink` | problem | Every deserialization sink call (gadget triage) |
| Unsafe deserialization chain | `java/deserialization/unsafe-chain` | path | Remote/user source → deserialization sink (RCE chain) |
| Unsafe polymorphic deserialization type | `java/deserialization/unsafe-type` | path | Remote source → polymorphic type descriptor (Jackson/Jodd/Gson) |
| Unsafe RMI deserialization | `java/deserialization/rmi` | path | A remote object with a complex-typed method is exported & bound |
| Apache Dubbo deserialization chain | `java/deserialization/dubbo-chain` | path | Dubbo `Codec2.decodeBody(...)` → `ObjectInput.readXXX(...)` (CVE-2020-11995 style) |

Generic sinks (queries 1–3): `ObjectInputStream.readObject/readUnshared`,
`XMLDecoder`, XStream, Kryo, SnakeYAML, Jackson polymorphic, Hessian/Burlap,
Jodd, Gson, Fastjson, JsonIo, Jabsorb, `ObjectMessage.getObject()` — all from
`codeql/java-all`'s `UnsafeDeserializationSink` model.

### Python (CWE-502)
| Query | `@id` | Kind | What it finds |
|---|---|---|---|
| Deserialization sink | `python/deserialization/sink` | problem | Every insecure decoding (pickle/marshal/yaml/shelve/dill/...) |
| Unsafe deserialization chain | `python/deserialization/unsafe-chain` | path | Remote/user source → insecure decoding sink |

Sinks: `pickle.load(s)`, `cPickle.*`, `marshal.load(s)`, `yaml.load` (without
`SafeLoader`/`CSafeLoader`), `shelve.open`, `dill.load(s)`, `jsonpickle.decode`,
`pandas.read_pickle` — from `codeql/python-all`'s `Decoding` model
(`mayExecuteInput()`).

## Quickstart

```bash
# 1. Install CodeQL CLI (https://github.com/github/codeql-cli-binaries/releases)
codeql --version

# 2. From the repo root, resolve & install the local packs (workspace-aware)
codeql pack install java/qlpack.yml python/qlpack.yml tests/java/qlpack.yml tests/python/qlpack.yml

# 3. Create a database for your target
codeql database create my-java-db --language=java   --command="mvn -B compile -q"
codeql database create my-py-db   --language=python

# 4a. Run the published packs from the registry
codeql database analyze my-java-db hypnguyen1209/java-deserialization   --format=sarif-latest --output=java.sarif
codeql database analyze my-py-db   hypnguyen1209/python-deserialization --format=sarif-latest --output=py.sarif

# 4b. ...or run the local suites (no publish needed)
codeql database analyze my-java-db java/suites/java-deserialization.qls   --search-path=java   --format=sarif-latest --output=java.sarif
codeql database analyze my-py-db   python/suites/python-deserialization.qls --search-path=python --format=sarif-latest --output=py.sarif
```

## Using as a custom query suite in GitHub Advanced Security

```yaml
# .github/codeql/codeql-config.yml
packs:
  - source: "hypnguyen1209/java-deserialization"
  - source: "hypnguyen1209/python-deserialization"
```

## Tests

Each query ships a vulnerable and a safe fixture under `tests/`. The pack
currently has 6 passing tests (4 Java, 2 Python):

```bash
codeql test run tests/java tests/python   # All 6 tests passed
```

Use `codeql test run --learn <dir>` to (re)generate `.expected` files, then
review the diff by hand.

## Extending the sink model

The Dubbo query (`DubboDeserializationModel.qll`) is the reference example: it
defines its own source (`Codec2.decodeBody` params), sink (`ObjectInput.readXXX`
qualifier) and extra taint steps (`Serialization.deserialize`, the
`ObjectInput` constructor) instead of relying on the generic model. Follow the
same pattern to support other custom frameworks. See
[docs/extending.md](./docs/extending.md) and [docs/references.md](./docs/references.md).

## Publishing

Tagging a release (`v0.0.2`) triggers `.github/workflows/publish.yml`, which
publishes both packs to `ghcr.io/hypnguyen1209/*` using `GITHUB_TOKEN`.

## Acknowledgements & references

This pack stands on the shoulders of several open-source CodeQL resources. See
[docs/references.md](./docs/references.md) for the full list and how each one
informed this work. In particular:

- **Generic Java/Python models** reuse GitHub's official
  `codeql/java-all` and `codeql/python-all` (Apache-2.0).
- **Apache Dubbo chain** is adapted from the GreHack 2021 workshop by
  Alvaro Munoz (@pwntester) — `pwntester/codeql_grehack_workshop` (MIT).
- **RMI query** is adapted from GitHub's experimental
  `java/unsafe-deserialization-rmi` (Apache-2.0), surfaced via
  `webraybtl/CodeQLpy`.

## License

MIT — see [LICENSE](./LICENSE). The library packs it depends on
(`codeql/java-all`, `codeql/python-all`) are licensed by GitHub under their own
terms (https://github.com/github/codeql).
