# Design notes

Full research, schema verification and prior-art survey: `/workspace/openshell-kb/policy-annotations.md`
(on the owner's workspace). Key decisions implemented here:

- Output is hand-written YAML text re-parsed by `openshell_policy_schema::parse_policy`: the crate's
  serializer drops comments and sorts keys.
- Rule key per host (not per file) to keep OpenShell's binaries x endpoints cross product narrow;
  `rule=` opts into grouping.
- Drift compares typed `PolicyDocument`s, so comments/ordering/quoting never trigger drift; sections are
  labelled startup vs live.
- Provider credentials are never in policy.yaml (no such section) and never in generated files.
- Lint is AST based (tree-sitter 0.25: JS/TS/TSX, Python, Go, bash). The old regex engine fired ~990 fs-write warnings on Paperclip;
  the AST engine classifies the path argument (declared root / `/tmp` / temp-dir expression / absolute literal outside the
  roots / computed) and only the literal-outside case warns. Computed paths are summarised.
- `diff-logs` closes the loop: deny logs -> suggestions with an explicit `bin=` taken from the event (never guessed), placed
  at a source line that mentions the host, else in `openshell/observed-egress.sh`. Logs are lossy, so stale is advisory.
- Custom provider profiles: OpenShell has no providers section in policy.yaml; a profile is a gateway object
  (`openshell profile import -f`) attached with `sandbox create --provider`, contributing its endpoints (log policy name
  `_provider_<name>`). `[providers] profiles_dirs` lets a repo ship its own.
