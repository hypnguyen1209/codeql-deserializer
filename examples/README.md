# Examples — deep-debug targets

Runnable demo targets used to validate the query packs end-to-end against real
CodeQL databases (not just the unit tests under `tests/`). Each target
exercises every supported deserialization sink **and** its recognized-safe
variant, so you can confirm that:

- the sink-enumeration query finds every unsafe sink,
- the chain query fires only for remote-controlled sinks,
- recognized sanitizers/whitelists/safe constructors are excluded,
- the framework-specific queries (Dubbo/RMI/Spring) do **not** false-positive on
  unrelated code,
- our `UnsafeDeserialization.ql` produces the same results as GitHub's official
  `java/unsafe-deserialization` (parity).

See [`docs/deep-debug.md`](../docs/deep-debug.md) for the recorded results.

## Run

```bash
# from repo root, after: codeql pack install java/qlpack.yml python/qlpack.yml
powershell -ExecutionPolicy Bypass -File examples/run-debug.ps1   # Windows
bash examples/run-debug.sh                                         # Linux/macOS
```

## Layout

- `examples/java/` — `DeserTarget.java` + minimal framework stubs
  (ObjectInputStream/`readUnshared`, XMLDecoder, XStream, Kryo, SnakeYAML,
  Jackson polymorphic, Hessian) and safe variants (ValidatingObjectInputStream,
  SerialKiller, XStream `addPermission(NoTypePermission.NONE)`, Kryo
  `setRegistrationRequired(true)`, SnakeYAML `SafeConstructor`, Jackson
  `setPolymorphicTypeValidator`). Remote source: `Socket.getInputStream()`.
- `examples/python/app.py` — Flask app with `pickle`/`cPickle`/`marshal`/
  `yaml.load` (unsafe + `SafeLoader`/`CSafeLoader`)/`dill`/`jsonpickle`/
  `pandas.read_pickle`/`shelve.open` and a constant-input control. Remote
  source: `flask.request`.

The stubs carry the exact qualified names/signatures the official CodeQL
framework models match, so no external jars are required.
