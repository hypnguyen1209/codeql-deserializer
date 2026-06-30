# Extending the deserialization sink model

The query packs are deliberately thin: they delegate sink identification to a
single model file per language (or per framework) so you can add support in one
place.

## Generic sinks

### Java — `java/deserialization/DeserializationSinkModel.qll`

This re-exports GitHub's official `codeql/java-all` `UnsafeDeserializationSink`
as `JavaDeserializationSink` and the flow module as `JavaDeserializationFlow`.
`DeserializationSinks.ql`, `UnsafeDeserialization.ql` and
`UnsafeDeserializationType.ql` all consume it, so anything the official model
already covers (ObjectInputStream, XStream, Kryo, SnakeYAML, Jackson, Hessian,
Jodd, Gson, Fastjson, ...) is picked up automatically.

### Python — `python/deserialization/DeserializationSinkModel.qll`

Re-exports `codeql/python-all`'s `Decoding` (filtered by `mayExecuteInput()`)
as `PythonDeserializationSink` and `UnsafeDeserializationFlow` as
`PythonDeserializationFlow`. Add new decoders by modeling `Decoding::Range`
(see the official `codeql/python-all` Concepts library).

## Adding a custom framework (worked example: Apache Dubbo)

`DubboDeserializationModel.qll` is the reference example. It does **not** use
the generic sink; instead it defines its own source, sink and extra taint steps:

```codeql
// SOURCE: untrusted network input received by a Dubbo codec
class DubboCodecDecodeBody extends Method { ... }
module DubboDeserializationConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DubboCodecDecodeBody m | source.asParameter() = m.getAnUntrustedParameter())
  }
  predicate isSink(DataFlow::Node sink) { isDubboDeserializationSink(sink) }
  predicate isAdditionalFlowStep(DataFlow::Node fromNode, DataFlow::Node toNode) {
    // Serialization.deserialize(url, InputStream) : arg -> return
    // new ObjectInputImpl(InputStream)               : constructor arg -> instance
  }
}
module DubboDeserializationFlow = TaintTracking::Global<DubboDeserializationConfig>;
```

Follow the same pattern to support other RPC/serialization frameworks
(e.g. gRPC, Hessian through a custom SPI, custom Kafka decoders):
1. Define a `Source` — the framework's network entry-point parameters.
2. Define a `Sink` — the framework's deserialization call (usually the qualifier
   of a `readXXX`-style method).
3. Add `isAdditionalFlowStep` for any helper that bridges input to the
   deserializer (constructors, `deserialize(...)` helpers).
4. Add a vulnerable + safe fixture under `tests/<lang>/` and run
   `codeql test run --learn <dir>`.

## Stateful / gadget-aware tracking

For analyses that need to carry state along a path (e.g. tracking which gadget
class a value has flowed through), use `TaintTracking::GlobalWithState` with a
`DataFlow::StateConfigSig` instead of `ConfigSig`. See the
`RecursiveFlow` query in [trailofbits/codeql-queries](https://github.com/trailofbits/codeql-queries)
(`java/src/security/Recursion/Recursion.ql`) for a concrete example.

## Reachability triage (follow-up idea)

A deserialization sink is only exploitable if it is reachable from a remote
entry point. The chain queries already gate on `ActiveThreatModelSource`, but for
manual triage you can enumerate HTTP/RPC endpoints (Spring `@RequestMapping`,
JAX-RS, Servlet `do*`, etc.) and cross-reference with the sink list. See
[ice-doom/CodeQLRule](https://github.com/ice-doom/CodeQLRule)
(`ApplicationRoutes/SpringMVC`) for a Spring MVC route-enumeration helper that
can be adapted for this.

## API notes (current CodeQL)

- Build a config with `module C implements DataFlow::ConfigSig { ... }` and a
  flow with `module F = TaintTracking::Global<C>;`.
- Path queries: `import F::PathGraph` then `F::flowPath(source, sink)` — note
  `flowPath` is **2-argument** in the current API.
- Use `MethodCall` (not the older `MethodAccess`).
- Library packs: import `semmle.code.java.security.UnsafeDeserializationQuery`
  (Java) and `semmle.python.security.dataflow.UnsafeDeserializationQuery` (Python).
