# java/python deserialization — CodeQL query packs

Curated [CodeQL](https://codeql.github.com/) query packs for finding
**deserialization sinks** and **source-to-sink chains** in **Java** and
**Python** codebases. Published to the GitHub Container Registry as
`hypnguyen1209/java-deserialization` and `hypnguyen1209/python-deserialization`.

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
├── java/                # Java query pack
│   ├── qlpack.yml
│   ├── suites/java-deserialization.qls
│   └── deserialization/
│       ├── DeserializationSinks.ql          # enumerate every deserialization sink (problem)
│       ├── UnsafeDeserialization.ql          # remote/user source -> deserialization sink (path)
│       ├── UnsafeDeserializationType.ql      # remote -> polymorphic type descriptor (path)
│       └── DeserializationSinkModel.qll       # reusable sink model (extends codeql libs)
├── python/              # Python query pack
│   ├── qlpack.yml
│   ├── suites/python-deserialization.qls
│   └── deserialization/
│       ├── DeserializationSinks.ql
│       ├── UnsafeDeserialization.ql
│       └── DeserializationSinkModel.qll
├── tests/               # vulnerable + safe fixtures with .expected files
│   ├── java/
│   └── python/
├── .github/workflows/   # check-queries (compile + test), publish (GHCR)
├── codeql-workspace.yml  # registers the four local packs as a workspace
└── docs/extending.md     # how to add new sinks
```

## Queries

### Java (CWE-502)
| Query | Kind | What it finds |
|---|---|---|
| `java/deserialization/sink` | problem | Every deserialization sink call (gadget triage) |
| `java/deserialization/unsafe-chain` | path | Remote/user source → deserialization sink (RCE chain) |
| `java/deserialization/unsafe-type` | path | Remote source → polymorphic type descriptor (Jackson/Jodd/Gson) |

Sinks covered: `ObjectInputStream.readObject/readUnshared`, `XMLDecoder`,
XStream, Kryo, SnakeYAML, Jackson polymorphic, Hessian/Burlap, Jodd, Gson,
Fastjson, JsonIo, Jabsorb, `ObjectMessage.getObject()` — all from
`codeql/java-all`'s `UnsafeDeserializationSink` model.

### Python (CWE-502)
| Query | Kind | What it finds |
|---|---|---|
| `python/deserialization/sink` | problem | Every insecure decoding (pickle/marshal/yaml/shelve/dill/...) |
| `python/deserialization/unsafe-chain` | path | Remote/user source → insecure decoding sink |

Sinks covered: `pickle.load(s)`, `cPickle.*`, `marshal.load(s)`,
`yaml.load` (without `SafeLoader`/`CSafeLoader`), `shelve.open`, `dill.load(s)`,
`jsonpickle.decode`, `pandas.read_pickle` — all from `codeql/python-all`'s
`Decoding` model (filtered by `mayExecuteInput()`).

## Quickstart

```bash
# 1. Install CodeQL CLI (https://github.com/github/codeql-cli-binaries/releases)
codeql --version

# 2. From the repo root, resolve & install the four local packs (workspace-aware)
codeql pack install java/qlpack.yml
codeql pack install python/qlpack.yml
codeql pack install tests/java/qlpack.yml
codeql pack install tests/python/qlpack.yml

# 3. Create a database for your target
codeql database create my-java-db --language=java   --command="mvn -B compile -q"
codeql database create my-py-db   --language=python

# 4a. Run the published packs from the registry
codeql database analyze my-java-db hypnguyen1209/java-deserialization   --format=sarif-latest --output=java.sarif
codeql database analyze my-py-db   hypnguyen1209/python-deserialization --format=sarif-latest --output=py.sarif

# 4b. ...or run the local query suites (no publish needed)
codeql database analyze my-java-db java/suites/java-deserialization.qls   --search-path=java   --format=sarif-latest --output=java.sarif
codeql database analyze my-py-db   python/suites/python-deserialization.qls --search-path=python --format=sarif-latest --output=py.sarif
```

Run a single query:

```bash
codeql query run java/deserialization/UnsafeDeserialization --database=my-java-db --search-path=java
```

## Using as a custom query suite in GitHub Advanced Security

Add to `.github/codeql/codeql-config.yml`:

```yaml
packs:
  - source: "hypnguyen1209/java-deserialization"
  - source: "hypnguyen1209/python-deserialization"
```

## Tests

Each query ships a vulnerable and a safe fixture under `tests/`. Run:

```bash
codeql test run tests/java tests/python
```

Use `codeql test run --learn <dir>` to (re)generate `.expected` files, then
review the diff by hand.

## Extending the sink model

Add new sinks to `DeserializationSinkModel.qll` (Java/Python) and re-run
`codeql test run`. See [docs/extending.md](./docs/extending.md).

## Publishing

Tagging a release (`v0.0.1`) triggers `.github/workflows/publish.yml`, which
publishes both packs to `ghcr.io/hypnguyen1209/*` using `GITHUB_TOKEN`. To
publish manually:

```bash
echo "$GH_TOKEN" | codeql package publish --github-auth-stdin java/qlpack.yml
echo "$GH_TOKEN" | codeql package publish --github-auth-stdin python/qlpack.yml
```

## License

MIT — see [LICENSE](./LICENSE). The library packs it depends on
(`codeql/java-all`, `codeql/python-all`) are licensed by GitHub under their own
terms (see https://github.com/github/codeql).
