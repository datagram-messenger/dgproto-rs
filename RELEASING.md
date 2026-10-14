# Releasing dgproto-rs

This document is for maintainers with write access to the repository.

## Versioning

This crate follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html):

| Bump | When |
|------|------|
| **Patch** (`0.x.z`) | Bug fixes, documentation, test improvements. No public API or wire-format change. |
| **Minor** (`0.x.0`) | Backwards-compatible new features or public API additions. |
| **Major** (`x.0.0`) | Breaking public API changes or wire-format changes requiring a DGProto v1 spec update. |

The DGProto v1 protocol specification is versioned independently from this
crate. A crate version does **not** imply wire compatibility with a specific
protocol revision.

## Step-by-step: cutting a release

### 1. Trigger the release-prep workflow

Go to **Actions → Release prep → Run workflow** and enter the new version
(e.g. `0.5.0`, no `v` prefix). The workflow will:

- Create a branch `chore/release-v<version>`.
- Bump the version in `Cargo.toml` and update `Cargo.lock`.
- Open a pull request against `main`.

### 2. Review and merge the PR

- Confirm `Cargo.toml` has the correct version.
- Ensure all CI checks pass.
- Merge using **squash** or **rebase** (no merge commits on `main`).

### 3. Push the release tag

After the PR is merged:

```sh
git checkout main
git pull
git tag v<version>           # e.g. git tag v0.5.0
git push origin v<version>
```

The tag push triggers the **Release** workflow (`release.yml`), which:

1. Re-runs the full CI suite (test, clippy, fmt, doc, MSRV) as a final gate.
2. Verifies the tag matches the version in `Cargo.toml`.
3. Publishes the crate to [crates.io](https://crates.io/crates/dgproto) using
   the `CARGO_REGISTRY_TOKEN` secret.
4. Creates a GitHub Release with the changelog section for this version.

### 4. Verify the release

- Confirm the crate appears on [crates.io/crates/dgproto](https://crates.io/crates/dgproto).
- Confirm the GitHub Release is created with the correct release notes.
- Confirm [docs.rs/dgproto](https://docs.rs/dgproto) builds successfully (may
  take a few minutes after publication).

## Release notes

Release notes are generated **automatically** by
[git-cliff](https://git-cliff.org/) when the release tag is pushed. They
appear in the GitHub Release — there is no `CHANGELOG.md` file in this
repository.

git-cliff reads the Conventional Commits history and groups entries by type
(`feat`, `fix`, `perf`, `refactor`, `docs`, `test`). `chore`, `ci`, and
`style` commits are excluded. The configuration lives in `cliff.toml`.

To preview what the release notes will look like locally:

```sh
cargo install git-cliff --locked
git-cliff --config cliff.toml --unreleased
```

## Required GitHub secrets and settings

| Secret / setting | Where to set | Purpose |
|---|---|---|
| `CARGO_REGISTRY_TOKEN` | Repository → Settings → Secrets → Actions | Publish to crates.io |
| `crates-io` environment | Repository → Settings → Environments | Optional approval gate before publish |

To obtain a crates.io token: log in to [crates.io](https://crates.io), go to
**Account Settings → API Tokens**, and create a token scoped to
**publish-new** and **publish-update** for the `dgproto` crate.
