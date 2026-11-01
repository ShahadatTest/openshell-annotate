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
