# Changelog

## 0.0.1 — 2026-06-30
- Initial public release.
- Java query pack (`codeql-db/java`): `DeserializationSinks`, `UnsafeDeserialization` (chain), `UnsafeDeserializationType` (polymorphic type control). Reuses the `codeql/java-all` CWE-502 sink model.
- Python query pack (`codeql-db/python`): `DeserializationSinks`, `UnsafeDeserialization` (chain). Reuses the `codeql/python-all` `Decoding` model.
- Test fixtures for both languages (vulnerable + safe) with committed `.expected` files.
- GitHub Actions: `check-queries` (compile + test) and `publish` (to GHCR).
