# Extending the deserialization sink model

The query packs are deliberately thin: they delegate sink identification to a
single model file per language so you can add framework support in one place.

## Java — `java/deserialization/DeserializationSinkModel.qll`

Extend `JavaDeserializationSink` (a `TaintTracking::Sink`) with new call
predicates:

```codeql
class JavaDeserializationSink extends TaintTracking::Sink, MethodAccess {
  JavaDeserializationSink() {
    // existing sinks ...
    // new framework, e.g. Apache Ignite
    this.getMethod().hasSignature("readObject", 1, _)
    and this.getMethod().getDeclaringType().getASupertype*().hasName("IgniteObjectInput")
  }

  override Expr asSinkExpr() { this.getArgument(0) }
}
```

Then `UnsafeDeserialization.ql` and `DeserializationSinks.ql` pick it up
automatically.

## Python — `python/deserialization/DeserializationSinkModel.qll`

Extend `PythonDeserializationSink` (a `TaintTracking::Sink`):

```codeql
class PythonDeserializationSink extends TaintTracking::Sink {
  PythonDeserializationSink() {
    this.asCall().(CallNode).getFunc().(Attribute).getName() = "load"
    and this.asCall().(CallNode).getFunc().(Attribute).getAttr() ...
  }
  ...
}
```

Add a matching safe/vulnerable fixture under `tests/<lang>` and run
`codeql test run`.
