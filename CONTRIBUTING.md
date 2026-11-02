# Contributing

Thanks for helping. openshell-annotate is an independent community project (not affiliated with NVIDIA).

## Before you open a pull request

- Open an issue first for anything beyond a small fix, so we agree on the direction.
- Add a test for every new directive, attribute, lint pattern or error message (`tests/cli.rs`; fixtures in
  `tests/fixtures/`). If generated output changes, review `tests/fixtures/sample/policy.expected.yaml` by hand.
- Never emit a field that the pinned `openshell-policy-schema` rejects.
- No secrets in code, fixtures or test output.

## Checks (CI runs the same)

```
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
scripts/gen-docs.sh --check      # regenerate with scripts/gen-docs.sh when directives or flags change
```

## Developer Certificate of Origin (DCO)

Every commit must be signed off, certifying that you wrote the change or have the right to submit it under the
project's Apache-2.0 license (https://developercertificate.org/):

```
git commit -s -m "your message"      # adds: Signed-off-by: Your Name <you@example.com>
```

To fix a missing sign-off: `git commit --amend -s` (last commit) or `git rebase --signoff main`.
The sign-off name and email must match your commit author.

## License

By contributing you agree that your contributions are licensed under the Apache License 2.0 (see `LICENSE`).
