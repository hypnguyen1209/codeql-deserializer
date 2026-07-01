# Changelog

## 0.1.0 — 2026-07-01
- #1 GadgetChainPath.ql: real **`@kind path-problem`** gadget chain. Builds its own
  PathGraph over the static call graph + framework-dispatch edges (depth-capped to
  8 hops) so the full chain `readObject -> ... -> hashCode -> invoke -> exec` renders
  as an explorable SARIF code-flow / VS Code path, not just the two endpoints.
- #1 GadgetChainSteps.ql: bounded (≤4 hops) non-recursive call-path *string* rendering
  (readObject -> helper -> exec) for the plain-text Markdown CLI reports.
- #4 Framework-dispatch edges reworked in GadgetModel (the call-graph analog of
  `isAdditionalFlowStep`), now two conservative patterns that also render inside the
  gadget-chain-path graph:
  - (a) same-verb virtual dispatch (proxy `InvocationHandler.invoke`,
    `Comparator.compare`, `Map.get/entrySet`), and
  - (b) **contained-value container dispatch** — an outer gadget that embeds a field
    of an inner gadget's type reaches the inner's container-triggered callback
    (`HashMap.readObject -> key.hashCode()`, `TreeMap.readObject -> key.compareTo()`),
    which the same-name heuristic structurally missed.
  - FP fix: pattern (a) no longer treats an RCE action call (e.g. `Method.invoke`,
    the sink) as a dispatch edge, which had wired unrelated gadgets together.
  - New fixtures EvilMapHolder + EvilHashKey exercise `readObject -> (dispatch) ->
    hashCode -> Method.invoke`.
- #5 Catalog + decompiler expansion:
  - Actions: JMX `MBeanServer.invoke`, Groovy `GroovyShell`/`GroovyClassLoader`, JShell,
    OGNL, MVEL, Spring SpEL, Velocity, Freemarker, and javassist `ProxyFactory` /
    `Proxy.newProxyInstance`.
  - Sinks (`ExtraDeserializationSinkCall`): `Hessian2Input`/`HessianInput`, Kryo
    `readClassAndObject`/`readObject` (incl. pool variants), and the RMI/JMX-remote
    `MarshalledObject.get()` + `javax.management.remote.rmi.RMIConnection` primitives;
    surfaced by the `sink` query and treated as dangerous by find-gadget-deser.
  - Known-gadget catalog: +ROME, Click, Vaadin, BeanShell, Jython, Clojure, Hibernate,
    MySQL/DBCP JDBC, `JdbcRowSetImpl`, `BadAttributeValueExpException`, etc.
  - Decompiler choice in find-gadget-deser.py: `--decompiler cfr|procyon|jadx`
    (procyon jar auto-downloaded; jadx from PATH) for jars CFR can't parse.
  - New test fixtures + stubs (extrasinktest/ExtraSinks) cover the Hessian/Kryo sinks.
- #3 Tooling quick wins:
  - `--threads` now defaults to **0 (one per core)** and is passed to *both*
    `database create` and `database analyze` in hunt.py and find-gadget-deser.py
    (they no longer run single-threaded).
  - **SARIF is always emitted** alongside the Markdown report (`<out>.sarif`), not
    only when `--sarif` is passed — open it in VS Code / GitHub code scanning.
  - find-gadget-deser.py **skips CFR decompile+build when the DB is already cached**
    for the jar's sha256 (re-runs no longer rebuild from scratch); `--keep-decompiled`.
  - **Depth cap** on call-graph reachability: `gadgetMaxCallDepth()` (10 hops) bounds
    the `calls*` closures in GadgetModel + HuntReachabilityModel so queries don't blow
    up on huge decompiled-jar databases.
- #2 benchmark/: cc1 (commons-collections-style) + beanutils BeanComparator + safe
  control, with bench.py measuring recall/precision. Currently recall 100%, precision 100%
  (bench caught a real fixture bug: LazyMap must implement Map to be a recognized dispatch link).
- #7 tools/gen-poc.py: from a find-gadget-deser SARIF hit, emit a minimal Java
  serialize->deserialize PoC skeleton (TODO markers; validation is yours). Now prints
  an authorization warning on every run and REFUSES to write the harness without an
  explicit `--yes-i-have-authorization` ack; the skeleton stays non-armed
  (`buildGadget()` throws) by design.
- 14 unit tests pass; README updated (15 queries, new tools).



## 0.0.7 — 2026-07-01
- 	ools/find-gadget-deser.py: scoped JAR gadget finder. --jar x.jar --start-class 
  Main -> decompiles with CFR (auto-cached), builds a buildless CodeQL DB, generates
  a reachability query scoped to the start class, and reports chains
  start-method -> ... -> deserialization sink OR RCE gadget action.
- java/gadgets/HuntReachabilityModel.qll: DangerousCall (deserialize sink + RCE
  action) + reachableDangerousFrom call-graph reachability; consumed by the
  generated query template (java/_generated/, gitignored).
- --full also runs the global gadget/sink suite. Tested on a real test jar
  (finds readObject + Runtime.exec chains from a Spring-style main class).
- README + docs/hunting-guide.md document the JAR/start-class workflow. 13/13 tests.

## 0.0.6 — 2026-07-01
- Daily-driver hunting: 	ools/hunt.py CLI builds a buildless CodeQL DB
  (--build-mode=none) and runs gadget/sink suites, emitting a ranked Markdown
  report.
- New hunting queries: GadgetDispatchChain.ql (Serializable link method ->
  RCE action; e.g. Comparator/InvocationHandler/Map dispatch gadgets) and
  NovelGadgetCandidates.ql (entry/dispatch -> action, excluding the known
  ysoserial catalog -> candidate NEW gadgets).
- Model: deterministic action-severity ranking; getSourceDeclaration() for
  parameterized interfaces (Comparator/Map) so generic dispatch gadgets are
  recognized in buildless mode.
- docs/hunting-guide.md daily workflow; xamples/ysoserial-hunt-report.md`n  real run on frohoff/ysoserial (48 findings: 1 chain, 45 actions, 1 entry,
  1 novel).
- Suites: java-gadgets.qls, java-deserialization.qls, java-all.qls. 13/13 tests.

## 0.0.5 — 2026-07-01
- Java: added ysoserial-style deserialization gadget detection under java/gadgets/:
  GadgetEntryPoints.ql (Serializable readObject/readResolve/readExternal),
  GadgetActionCalls.ql (RCE primitives: Runtime.exec, Method.invoke, JNDI
  lookup, Templates.newTransformer, ...), DeserializationGadgetChain.ql`n  (entry -> action call-graph reachability), KnownYsoserialGadgetClasses.ql`n  (catalog: InvokerTransformer, TemplatesImpl, BeanComparator, ...).
- GadgetModel.qll models entry/link/action, restricted to target source.
- New suites java-gadgets.qls and java-all.qls (10 Java queries total).
- Tests: 4 gadget fixtures (vulnerable flagged, safe not); 11/11 tests pass.
- Real-DB check: gadget queries give 0 false positives on the generic
  examples/java DeserTarget database.

## 0.0.4 — 2026-06-30
- Deep-debug validation: ran all packs against real CodeQL databases built from
  a comprehensive xamples/ target (8 Java sinks across 8 frameworks + 6
  recognized-safe variants; 10 Python sinks + safe YAML/CSafeLoader).
- Confirmed parity with official java/unsafe-deserialization (same 8 results).
- Confirmed no false positives from Dubbo/RMI/Spring queries on generic code.
- Added xamples/ (runnable demo + run-debug scripts) and docs/deep-debug.md.

## 0.0.3 — 2026-06-30
- Java: added UnsafeSpringExporter.ql + SpringExporterModel.qll — Spring remoting
  exporter (@Bean returning a RemoteInvocationSerializingExporter/HessianExporter),
  a configuration-level deserialization sink. Adapted from GitHubSecurityLab/
  CodeQL-Community-Packs (UnsafeSpringExporterLib.qll).
- Tests: added Spring exporter fixture (vulnerable @Bean flagged, safe plain bean not);
  7/7 tests pass.
- Docs: credited GitHubSecurityLab/CodeQL-Community-Packs and github/codeql in
  docs/references.md.

## 0.0.2 — 2026-06-30
- Java: added `UnsafeDeserializationRmi.ql` — RMI deserialization via binding a
  remote object with a complex-typed method (adapted from GitHub's experimental
  `java/unsafe-deserialization-rmi`).
- Java: added `DubboDeserialization.ql` + `DubboDeserializationModel.qll` — Apache
  Dubbo `Codec2.decodeBody` → `ObjectInput.readXXX` chain (CVE-2020-11995 style),
  adapted from the GreHack 2021 workshop (@pwntester).
- Tests: added RMI and Dubbo fixtures (vulnerable flagged, safe not flagged);
  6/6 tests pass.
- Docs: added `docs/references.md` crediting the integrated & referenced repos.
- README: expanded query/coverage tables.

## 0.0.1 — 2026-06-30
- Initial public release.
- Java query pack: `DeserializationSinks`, `UnsafeDeserialization` (chain),
  `UnsafeDeserializationType` (polymorphic type control). Reuses `codeql/java-all`.
- Python query pack: `DeserializationSinks`, `UnsafeDeserialization` (chain).
  Reuses `codeql/python-all`.
- Test fixtures for both languages (vulnerable + safe) with committed `.expected`.
- GitHub Actions: `check-queries` (compile + test) and `publish` (to GHCR).
