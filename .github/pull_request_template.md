<!-- One line: what this changes and why. -->

## Summary

## Checklist

- [ ] Commit subjects follow [Conventional Commits](../CONTRIBUTING.md#commit-convention) (`type(scope): imperative subject`) — the `commits` job checks this
- [ ] `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` run locally
- [ ] Touches `crates/bunnyhopfix/src/windows.rs`? Say whether it was tested on a real Windows install — CI cannot run the game
- [ ] Does this need a version bump in the root `Cargo.toml`? (Only if you are preparing a `dev` → `main` release.)

The changelog is generated from the commit messages by git-cliff at release
time, so **no manual `CHANGELOG.md` edit is needed** — the `changelog-preview`
job summary shows how your commits will read. Edit `CHANGELOG.md` only if you
deliberately want curated prose for a release: a hand-written `## [<version>]`
section is used verbatim instead of the generated one.
