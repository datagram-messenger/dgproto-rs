## Summary

<!-- One paragraph: what this PR does and why. -->

## Type of change

<!-- Check all that apply. -->

- [ ] `feat` — new feature or module
- [ ] `fix` — bug fix
- [ ] `test` — tests only (no production code change)
- [ ] `refactor` — code restructuring, no behaviour change
- [ ] `docs` — documentation only
- [ ] `chore` — build, CI, dependencies
- [ ] `perf` — performance improvement
- [ ] Breaking change (add `BREAKING CHANGE:` footer to the commit message)

## Related issues

<!-- Closes #<issue> -->

---

## Checklist

### All PRs

- [ ] PR title follows Conventional Commits format: `<type>(<scope>): <description>`.
- [ ] Commits follow Conventional Commits (see `CONTRIBUTING.md §Commit convention`).
- [ ] `cargo fmt --all` applied (no formatting diff).
- [ ] `cargo clippy --all-targets -- -D warnings` passes.
- [ ] `cargo test --all-features` passes.
- [ ] `cargo test --release --all-features` passes.
- [ ] `cargo doc --all-features --no-deps` passes (no broken links, no missing docs).

### Code changes

- [ ] New or changed behaviour is covered by unit tests.
- [ ] Failure / boundary paths are tested.
- [ ] No `unwrap()` / `expect()` on untrusted data in non-test code.
- [ ] No new `unsafe` without a `// SAFETY:` comment.
- [ ] No key material in tests, logs, or committed files.

### Wire / protocol changes

- [ ] Wire-vector tests (`cargo test wire_vectors`) pass.
- [ ] The DGProto v1 spec has been updated (or a spec PR is linked above).
- [ ] `testdata/vectors/` updated if wire bytes changed.
- [ ] Cross-language parity verified against `dgproto-go`.

### Public API changes

- [ ] Semver impact assessed (patch / minor / major).
- [ ] `README.md` updated if the quick-start example or feature list changed.
- [ ] `docs/` updated if observable behaviour changed.

### Dependencies

- [ ] No new dependency added without justification in the PR body.
- [ ] `Cargo.lock` committed.
- [ ] No `ring`, `async-std`, `anyhow`, or `serde` (for wire encoding) introduced.
