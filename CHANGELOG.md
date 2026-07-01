# Changelog

## 0.1.0 — 2026-07-01
- #1 GadgetChainSteps.ql: bounded (≤4 hops) non-recursive call-path rendering
  (readObject -> helper -> exec) so chains are visible, not just endpoints.
- #4 Framework-dispatch edges in GadgetModel (HashMap/TreeMap readObject ->
  hashCode/compare, proxy -> InvocationHandler.invoke) via dispatchEdge+, widening
  gadget reachability beyond the static call graph.
- #5 Expanded action catalog: JMX MBeanServer.invoke, Groovy GroovyShell/GroovyClassLoader,
  JShell, OGNL, MVEL, Spring SpEL, Velocity, Freemarker; + expanded known-gadget catalog.
- #3 Tooling quick wins: --threads, --sarif output, DB cache by jar sha256,
  --keep-decompiled in find-gadget-deser.py; --threads/--sarif in hunt.py.
- #2 benchmark/: cc1 (commons-collections-style) + beanutils BeanComparator + safe
  control, with bench.py measuring recall/precision. Currently recall 100%, precision 100%
  (bench caught a real fixture bug: LazyMap must implement Map to be a recognized dispatch link).
- #7 tools/gen-poc.py: from a find-gadget-deser SARIF hit, emit a minimal Java
  serialize->deserialize PoC skeleton (TODO markers; validation is yours).
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
