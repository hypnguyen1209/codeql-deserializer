# Deep-debug results

This records the end-to-end validation of the query packs against real CodeQL
databases built from [`examples/`](../examples/), run with CodeQL CLI 2.25.6
against `codeql/java-all@9.1.2` and `codeql/python-all@7.1.2`.

Reproduce with `examples/run-debug.ps1` (Windows) or `examples/run-debug.sh`
(Linux/macOS).

## Java — `examples/java/` (DeserTarget + framework stubs)

Remote source: `java.net.Socket.getInputStream()` (an `ActiveThreatModelSource`
via models-as-data). 14 methods: 8 vulnerable + 6 recognized-safe.

### `DeserializationSinks.ql` (`java/deserialization/sink`) — 8 results

| Line | Method | Sink | Expected |
|---|---|---|---|
| 29 | `oisObject` | `ObjectInputStream.readObject` | ✅ flagged |
| 35 | `oisUnshared` | `ObjectInputStream.readUnshared` | ✅ flagged |
| 41 | `xmlDecoder` | `XMLDecoder.readObject` | ✅ flagged |
| 60 | `xstream` | `XStream.fromXML` | ✅ flagged |
| 75 | `kryo` | `Kryo.readClassAndObject` | ✅ flagged |
| 89 | `snakeyaml` | `Yaml.load` | ✅ flagged |
| 103 | `jackson` | `ObjectMapper.readValue` (default typing) | ✅ flagged |
| 117 | `hessian` | `HessianInput.readObject` | ✅ flagged |

Recognized-safe variants (correctly **not** flagged):

| Line | Method | Why safe |
|---|---|---|
| 47 | `validatingOis` | `ValidatingObjectInputStream` (commons-io whitelist) |
| 53 | `serialKiller` | `SerialKiller` (org.nibblesec.tools) |
| 68 | `xstreamSafe` | `addPermission(NoTypePermission.NONE)` whitelist |
| 83 | `kryoSafe` | `setRegistrationRequired(true)` |
| 95 | `snakeyamlSafe` | `new Yaml(new SafeConstructor())` |
| 111 | `jacksonSafe` | `setPolymorphicTypeValidator(...)` |

### `UnsafeDeserialization.ql` (`java/deserialization/unsafe-chain`) — 8 results

Same 8 lines as the sink table above (each unsafe sink is reached from the
remote socket source).

### Parity with the official query

`codeql/java-queries` `java/unsafe-deserialization` returns **the same 8
results on the same 8 lines**. Our chain query reuses the official
`UnsafeDeserializationFlow` module, so it is behaviourally identical — no
regressions, no duplicate logic.

### Framework-specific queries — 0 false positives on this DB

Running the full `java-deserialization.qls` suite against `examples/java`:

| Query | Results |
|---|---|
| `java/deserialization/sink` | 8 |
| `java/deserialization/unsafe-chain` | 8 |
| `java/deserialization/unsafe-type` | 0 |
| `java/deserialization/dubbo-chain` | 0 |
| `java/deserialization/rmi` | 0 |
| `java/deserialization/spring-exporter` | 0 |

The Dubbo/RMI/Spring queries target framework-specific constructs (`Codec2`,
`java.rmi` remote objects, Spring `@Configuration`/`@Bean`) that are absent
here, so they correctly stay silent.

## Python — `examples/python/app.py` (Flask)

Remote source: `flask.request.get_data()`.

### `DeserializationSinks.ql` (`python/deserialization/sink`) — 10 results

| Line | Function | Sink | Expected |
|---|---|---|---|
| 18 | `vuln_pickle` | `pickle.loads` | ✅ |
| 24 | `vuln_cpickle` | `cPickle.loads` | ✅ |
| 30 | `vuln_marshal` | `marshal.loads` | ✅ |
| 36 | `vuln_yaml_unsafe` | `yaml.load` (no Loader) | ✅ |
| 54 | `vuln_dill` | `dill.loads` | ✅ |
| 60 | `vuln_jsonpickle` | `jsonpickle.decode` | ✅ |
| 66 | `vuln_pandas` | `pandas.read_pickle` | ✅ |
| 73 | `sink_only_shelve` | `shelve.open` | ✅ (sink only) |
| 79 | `safe_pickle_constant` | `pickle.loads` constant | ✅ (sink, no chain) |
| 86 | `safe_pickle_safeload` | `pickle.loads` (control) | ✅ |

Safe variants (correctly **not** flagged): `yaml.load(..., Loader=SafeLoader)`
(L42), `yaml.load(..., Loader=CSafeLoader)` (L48).

### `UnsafeDeserialization.ql` (`python/deserialization/unsafe-chain`) — 8 results

Lines 18, 24, 30, 36, 54, 60, 66, 86 — exactly the remote-controlled sinks.
Correctly **not** chained: `shelve.open("/tmp/x")` (L73, filename constant, no
remote flow) and `pickle.loads(b"\x80\x04\x95")` (L79, constant input).

## Findings

- **No bugs found.** Sink enumeration, chain detection, sanitizer/whitelist
  recognition and interprocedural constructor-taint steps all behave correctly.
- **Parity confirmed** between our Java chain query and the official
  `java/unsafe-deserialization`.
- **README coverage claims verified** against the model, including
  `jsonpickle.decode` and `shelve.open` (both flagged) and `cPickle`/`dill`/
  `pandas.read_pickle`.
- The framework-specific queries (Dubbo/RMI/Spring) introduce **no false
  positives** on generic deserialization code.

## Java gadgets — `tests/java/gadgettest/` (ysoserial-style)

| Query | Results | Notes |
|---|---|---|
| `java/deserialization/gadget-entry` | 2 | `EvilGadget.readObject`, `SafeGadget.readObject` (both are entry points; JDK internals excluded via `fromSource()`) |
| `java/deserialization/gadget-action` | 2 | `EvilGadget` `Runtime.exec`, `EvilHandler` `Method.invoke` |
| `java/deserialization/gadget-chain` | 1 | `EvilGadget.readObject` -> `exec` (safe `SafeGadget` correctly not chained) |
| `java/deserialization/known-gadget-class` | 1 | `org.apache.commons.collections.functors.InvokerTransformer` stub |

Cross-check: running the combined `java-all.qls` suite against the generic
`examples/java` DeserTarget database yields **0** results for all four gadget
queries (no false positives on code that only calls deserialization sinks but
defines no gadgets).