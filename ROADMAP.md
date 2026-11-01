# openshell-annotate roadmap

Order matters: each milestone builds on the previous one. All work stays local (no remote, nothing pushed) until Ilan approves.

| # | Milestone | Status |
|---|---|---|
| 1 | Auto-generated docs | done 2026-11-01 |
| 2 | Docker image | local build done 2026-11-01 (openshell-annotate:dev, 34.9 MB); registry publish pending Ilan's approval |
| 3 | GitHub Action + GitLab CI template | next |
| 4 | AI agent skill hardening and testing | blocked on logins |
| 5 | VS Code extension | last |

## 1. Auto-generated docs
- **Scope:** reference docs derived from the code, never hand-copied.
- **Deliverables:** `openshell-annotate docs [--out DIR] [--check]`; `docs/CLI.md` (clap help of every subcommand); `docs/DIRECTIVES.md` (from `src/spec.rs`, the table the parser also uses); `scripts/gen-docs.sh`; test `tests/docs.rs` fails when the committed docs are stale.
- **Depends on:** nothing. Every later milestone links to these docs.

## 2. Docker image (publish)
- **Scope:** small runtime image with the binary (tree-sitter grammars compiled in; distroless/cc base, 34.9 MB), entrypoint `openshell-annotate`, workdir `/src`.
- **Deliverables:** multi-stage `Dockerfile`, `scripts/docker-build.sh` (local tag `openshell-annotate:dev`), then, after approval, a publish workflow to a registry (ghcr.io) with version tags.
- **Depends on:** a public home for the repo and a resolvable dependency on `openshell-policy-schema` (today a `file://` git path to a local OpenShell checkout; the image build passes the checkout as a named build context). Publishing needs Ilan's approval and a remote.

## 3. GitHub Action + GitLab CI template
- **Scope:** run `lint --deny-warnings` and `drift --policy openshell/policy.yaml` on every pull/merge request; fail with annotations.
- **Deliverables:** composite GitHub Action (`action.yml`, uses the Docker image or a release binary), `.gitlab-ci.yml` include template, an example workflow, docs page, a fixture repo run in CI as self-test. Optional: sticky PR comment with the drift diff and `diff-logs` suggestions.
- **Depends on:** (1) docs to link from, (2) the Docker image.

## 4. AI agent skill hardening and testing
- **Scope:** make `skills/annotate-openshell-policy/SKILL.md` reliable for Claude Code and Cursor: scan code, add directives, loop on `lint` until clean.
- **Deliverables:** skill reads the generated `docs/DIRECTIVES.md` instead of duplicating grammar; an eval script that runs the agent on `annotate-demo` and the fixtures and scores `lint`/`drift` results; install instructions for each agent (`AGENTS.md`, Claude skill dir, Cursor rules).
- **Depends on:** (1) docs. **Blockers:** `claude` login on the dev server has expired (needs `claude` then `/login`); `cursor-agent` is not installed.

## 5. VS Code extension
- **Scope:** editor support for directives.
- **Deliverables:** TextMate grammar highlighting `@openshell` comments, diagnostics from `lint --json`, quick-fix to insert a suggested directive, command to preview the generated `policy.yaml`. Thin client over the CLI (binary path setting or the Docker image).
- **Depends on:** stable `--json` output of `lint`/`scan`/`generate` (add a schema doc), (2) for distribution. Marketplace publishing needs approval.
