# Changelog

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
