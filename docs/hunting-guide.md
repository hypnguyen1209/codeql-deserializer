# Daily gadget-chain hunting guide

This is a practical workflow for using `hypnguyen1209/java-deserialization` to hunt
deserialization gadget chains day-to-day. The companion CLI is
[`tools/hunt.py`](../tools/hunt.py).

## What the pack tells you

| Concept | Query | Meaning |
|---|---|---|
| **Sink** | `java/deserialization/sink`, `unsafe-chain` | where untrusted data is deserialized (and whether a remote source reaches it) |
| **Gadget entry** | `java/deserialization/gadget-entry` | a `Serializable` `readObject`/`readResolve`/`readExternal` — the chain start |
| **Gadget action** | `java/deserialization/gadget-action` | the RCE primitive a chain ends in (`Runtime.exec`, `Method.invoke`, JNDI `lookup`, `Templates.newTransformer`, `ClassLoader.loadClass`, `ScriptEngine.eval`, ...) |
| **Gadget chain** | `java/deserialization/gadget-chain` | a gadget entry that transitively reaches an RCE action via the call graph |
| **Dispatch gadget** | `java/deserialization/gadget-dispatch` | a serializable "link" method (`InvocationHandler.invoke`, `Comparator.compare`, `Map.get/put`, `equals/hashCode/toString`) that reaches an RCE action — the ysoserial "middle" gadgets |
| **Novel gadget** | `java/deserialization/novel-gadget` | entry/dispatch reaching an action but **not** in the known ysoserial catalog — your hunting target |
| **Known gadget class** | `java/deserialization/known-gadget-class` | a class from the ysoserial catalog present in source |

The headline hunting outputs are **gadget-chain**, **gadget-dispatch** and
**novel-gadget**: those say "this code, when deserialized, can reach RCE".

## Quick start

```bash
# one-time
codeql pack install java/qlpack.yml python/qlpack.yml

# hunt a target (buildless - no Maven/Gradle/deps needed for Java):
python tools/hunt.py /path/to/target --mode full --out report.md

# gadgets only (the ysoserial-style queries):
python tools/hunt.py /path/to/target --mode gadgets --out gadgets.md

# real build if buildless misses type info:
python tools/hunt.py /path/to/target --command "mvn -B compile -q"
```

`hunt.py` builds a CodeQL database (`--build-mode=none` for Java by default), runs
the chosen suite, and writes a ranked Markdown report grouped by rule and sorted
by severity (`[critical]` > `[high]` > `[medium]`).

## Worked example: ysoserial itself

Running the tool on `frohoff/ysoserial` (`--mode gadgets`) finds, among others:

- `java/deserialization/gadget-chain` (1) —
  `ExecMockSerializable.readObject()` reaches `Runtime.exec()` in
  `test/payloads/TestHarnessTest.java` (a real test gadget).
- `java/deserialization/gadget-action` (45) — the RCE primitives ysoserial uses
  (`Class.forName`, `Method.invoke`, `ClassLoader.loadClass`,
  `URL.openConnection`, `Runtime.exec`) across `payloads/util/Gadgets.java`,
  `util/Reflections.java`, `exploit/JBoss.java`, `exploit/JenkinsCLI.java`,
  `payloads/Hibernate1.java`, `payloads/MozillaRhino1.java`, ...
- `java/deserialization/novel-gadget` (1) — the `ExecMockSerializable` chain, not
  in the known catalog.

See [`examples/ysoserial-hunt-report.md`](../examples/ysoserial-hunt-report.md).

## Daily workflow

1. **Build DB.** For a library you suspect contains gadgets, `hunt.py <lib>
   --mode gadgets`. Buildless works for most source trees; use `--command` for a
   real build if type resolution looks weak (supertypes/overrides missing).
2. **Triage `novel-gadget` and `gadget-dispatch` first.** These are the candidate
   *new* gadgets. Open each: does the entry/link method really get triggered on
   deserialization (e.g. is the type `Serializable`, is the method reachable from
   `HashMap`/`TreeMap`/proxy `equals`/`hashCode`)?
3. **Cross-check with `known-gadget-class`.** If the library ships a known gadget
   class (`InvokerTransformer`, `TemplatesImpl`, `BeanComparator`, ...) AND you
   also found a reachable sink in the consuming app, that app is likely
   exploitable.
4. **Validate.** Build a minimal harness: serialize the candidate gadget, feed it
   to the app's sink, confirm the action fires. (Out of scope for this tool.)
5. **Extend.** If you find a new gadget class repeatedly, add it to
   `isKnownYsoserialGadgetClass` in `java/gadgets/GadgetModel.qll` and to the
   ysoserial catalog note in `docs/references.md`.

## Tuning / caveats

- **`gadget-chain`/`gadget-dispatch` use call-graph reachability** (`calls*`),
  which follows virtual dispatch. This is the right model for ysoserial (control
  flow through gadget methods, not data flow), but it can over-approximate:
  review each result for actual deserialization reachability.
- **Buildless extraction (`--build-mode=none`)** indexes all source without
  compiling, so type info for generics/supertypes can be weaker. If a `Comparator`
  /`Map` implementer is not flagged as a dispatch gadget, re-run with a real build
  (`--command`). The model uses `getSourceDeclaration()` to handle parameterized
  interfaces in both modes.
- **Precision**: `gadget-action` is intentionally broad (a triage list of RCE
  primitives in source). `gadget-chain`/`gadget-dispatch`/`novel-gadget` are the
  actionable ones.
- **Python**: the Python pack has sink/chain queries only (no gadget model —
  Python pickle gadgets are far fewer and mostly library-internal). Use
  `--lang python --mode sinks`.
