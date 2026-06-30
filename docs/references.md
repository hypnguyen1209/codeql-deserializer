# Acknowledgements & references

This pack combines GitHub's official CodeQL deserialization models with
framework-specific chain queries adapted from community resources. Everything
referenced here was studied and, where useful, integrated (modernized to the
current CodeQL `TaintTracking::Global` / `ConfigSig` / `flowPath` API and verified
to compile against `codeql/java-all@9.1.2` and `codeql/python-all@7.1.2`).

## What was integrated (code shipped in this repo)

| Source | License | Used for |
|---|---|---|
| [github/codeql](https://github.com/github/codeql) (`codeql/java-all`, `codeql/python-all`) | Apache-2.0 | Generic deserialization sink & flow models reused by `DeserializationSinks.ql`, `UnsafeDeserialization.ql`, `UnsafeDeserializationType.ql` (Java) and the Python queries. |
| [pwntester/codeql_grehack_workshop](https://github.com/pwntester/codeql_grehack_workshop) | MIT | `DubboDeserialization.ql` / `DubboDeserializationModel.qll` — the Apache Dubbo `Codec2.decodeBody` source + `ObjectInput.readXXX` sink + extra taint steps pattern (CVE-2020-11995 variants). |
| [webraybtl/CodeQLpy](https://github.com/webraybtl/CodeQLpy) | (see repo) | `UnsafeDeserializationRmi.ql` — pointed us to the RMI "binding unsafe remote object" deserialization surface; the modern, canonical version was taken from GitHub's experimental `java/unsafe-deserialization-rmi`. |
| [trailofbits/codeql-queries](https://github.com/trailofbits/codeql-queries) | Apache-2.0 | qlpack/suite conventions, query metadata style (`@group`, `@tags`, `@security-severity`) and the `DataFlow::GlobalWithState`/`StateConfigSig` pattern referenced in `docs/extending.md`. |

## What was referenced (studied for patterns / inspiration, no code copied)

| Source | Why referenced |
|---|---|
| [advanced-security/codeql-extractor-iac](https://github.com/advanced-security/codeql-extractor-iac) | Shows how a CodeQL extractor + library + query pack is structured for a non-standard language. Not integrated (out of scope: IaC, not Java/Python deserialization), but informed the qlpack/workspace layout. |
| [cldrn/codeql-queries](https://github.com/cldrn/codeql-queries) | Example of framework-specific source/sink modeling (Helidon) using the legacy `TaintTracking::Configuration`; informed the Dubbo extension example. |
| [ice-doom/CodeQLRule](https://github.com/ice-doom/CodeQLRule) | Spring MVC route/endpoint enumeration (`SpringMVCMapping.qll`) — useful for source-side reachability triage of which deserialization sinks are exposed to remote endpoints. Referenced in `docs/extending.md` as a follow-up idea. |
| [cor0ps/codeql](https://github.com/cor0ps/codeql) | A mirror/snapshot of the standard `github/codeql` libraries; used only as an offline reference of the official libraries. |
| [safe6Sec/CodeqlNote](https://github.com/safe6Sec/CodeqlNote) | Chinese CodeQL learning notes; used as a study reference for data-flow / sink-modeling idioms. |

## Notes on modernization

Several referenced queries predate the current CodeQL data-flow API. They use
`TaintTracking::Configuration` + `hasFlowPath` + `import DataFlow::PathGraph` and
`MethodAccess`. This pack rewrites those to the current API:

- `module Config implements DataFlow::ConfigSig { ... }` + `module Flow = TaintTracking::Global<Config>;`
- `import Flow::PathGraph` + `Flow::flowPath(source, sink)` (2-argument `flowPath`)
- `MethodCall` (the modern name for `MethodAccess`)

so that everything compiles against the latest `codeql/java-all` / `codeql/python-all`.
