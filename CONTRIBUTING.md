# Contributing

Pull requests welcome. Please:

1. Add or update a test fixture under `tests/<lang>/` covering your change
   (include a vulnerable case that should fire and a safe case that should not).
2. Run `codeql test run tests/java tests/python` locally and ensure all tests pass.
   Use `codeql test run --learn <dir>` to (re)generate `.expected` files, then
   review the diff by hand.
3. Keep query metadata (`@id`, `@kind`, `@security-severity`, `@tag`) consistent
   with the existing queries.
4. Document new sinks in README.md (coverage table) and docs/extending.md.
5. For a new known gadget class, add it to isKnownYsoserialGadgetClass in java/gadgets/GadgetModel.qll and re-test.
6. Try your change with python tools/hunt.py tests/java --mode full on a real target.

## Local setup

```bash
# install CodeQL CLI (https://github.com/github/codeql-cli-binaries/releases)
codeql pack install java/qlpack.yml python/qlpack.yml tests/java/qlpack.yml tests/python/qlpack.yml
codeql test run tests/java tests/python
```

## Releasing

Bump the `version:` in each `qlpack.yml`, commit the regenerated
`codeql-pack.lock.yml`, tag `vX.Y.Z`, and push. The `publish` workflow publishes
both packs to `ghcr.io/hypnguyen1209/*`.
