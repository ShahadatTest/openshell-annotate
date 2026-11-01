# openshell-annotate

Policy-as-code for [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) sandboxes. Developers write
structured comments next to the code that needs access; the CLI scans the repo and generates `policy.yaml`
(every entry commented with its reason and `file:line`) plus a separate providers file, lints for
un-annotated calls, and gates CI on drift.

Status: local prototype (M0 + core of M1 + a heuristic linter). Targets OpenShell policy schema v1
(`openshell-policy-schema` @ v0.1.6). Not published.

```ts
// @openshell egress api.openai.com:443 reason="LLM calls" access=read-write
// @openshell provider OPENAI_API_KEY
const r = await fetch("https://api.openai.com/v1/chat/completions", { ... });
```
```python
# @openshell fs write /workspace/data reason="result cache"
```

## Commands

| Command | What it does |
|---|---|
| `scan [PATHS] [--json]` | list directives with `file:line` (JS/TS, Python, Go, shell, Dockerfile comments; string-aware lexer) |
| `generate [PATHS] -o policy.yaml [--providers-out f.json\|f.sh] [--profiles-dir DIR]` | emit policy.yaml with a comment per entry; re-validated with the OpenShell schema crate; providers as JSON or a setup script |
| `lint [PATHS] [--policy policy.yaml] [--deny-warnings]` | directive validation + heuristic detection of un-annotated network calls, filesystem writes, secret reads, subprocesses; sanity-checks a policy file |
| `drift [PATHS] --policy policy.yaml [--providers f.json] [--strict]` | regenerate in memory and compare as typed documents; reports missing / extra / changed, tagged `startup` or `live` |

Exit codes: 0 clean, 1 findings/errors, 2 usage or I/O error.
`--root DIR` sets the repository root (paths in output are relative to it), `--config FILE` overrides
`<root>/openshell-annotate.toml`.

## Directive grammar

```ebnf
directive = "@openshell" , ws , body ;                 (* first thing in a comment line *)
body      = egress | provider | fs | bin | process | ignore ;
egress    = "egress" , ws , host , ":" , port , { "," , port } , { ws , attr } ;
provider  = "provider" , ws , ENV_NAME , { ws , attr } ;
fs        = "fs" , ws , ( "read" | "write" ) , ws , abs_path , { ws , attr } ;
bin       = "bin" , ws , abs_path ;
process   = "process" , { ws , attr } ;
ignore    = "ignore" , { ws , attr } ;
attr      = key , "=" , ( bare | '"' , text , '"' ) ;
```
Attributes: `reason` (required for egress, fs write, ignore), `access`, `protocol`, `allow`/`deny`
(`METHOD:/path`, repeatable), `enforce`, `tls=skip`, `bin`, `rule`, `scope=file`, provider `profile`/`name`,
process `user`/`group`, ignore `kind`. Unknown directives/attributes are errors, mirroring OpenShell's strict schema.

## Mapping to the OpenShell schema

| Directive | Output |
|---|---|
| `egress host:port` | `network_policies.<rule>.endpoints[]` (`host`, `port`/`ports`, `protocol`, `enforcement`, `access` or `rules`/`deny_rules`) + `binaries[]`; rule key = host slug unless `rule=` |
| binary | `bin=` > nearest `@openshell bin` in the file > `[languages]` in `openshell-annotate.toml`; missing = error (empty `binaries` allows nothing) |
| `fs read|write` | `filesystem_policy.read_only|read_write` (+ `include_workdir`, default true, because a present section defaults it to false) |
| `process` | `process.run_as_user|run_as_group` |
| `provider ENV` | **not** in policy.yaml: provider profile resolved from `credentials[].env_vars` in profile YAML (`--profiles-dir`), emitted as `providers.json` / `providers.sh` (`openshell provider create ... --credential ENV`) |
| `reason`, location | YAML comment only (OpenShell drops comments when it stores/returns a policy) |

## Config (`openshell-annotate.toml`, strict)

```toml
[languages]            # real executable path per language family inside the sandbox image
javascript = "/usr/local/bin/node"
python = "/usr/bin/python3.12"
go = "/opt/app/server"
shell = "/bin/bash"
[policy]
include_workdir = true
enforcement = "enforce"   # OpenShell's own default for inspected endpoints is "audit"
system_paths = "auto"     # auto: add /usr /lib /etc /proc /dev/urandom (ro) and /tmp /dev/null (rw) when there are
                          # no egress rules (the supervisor only adds them with network rules; without them nothing can exec);
                          # always | never
[providers]
profiles_dir = "/path/to/OpenShell/providers"
[providers.env]           # env var -> profile id overrides
[lint]
window = 8                 # lines a directive covers below it
exclude = []               # "^prefix/" anchors at the repo root; anything else is a substring of "/<relative path>"
categories = []            # restrict call-site heuristics to any of "net", "fs", "env", "exec" (empty = all)
[scan]
exclude = []               # same pattern syntax as [lint].exclude
```

## Limits (be aware)

- Lint is regex over a comment/string-masked token stream, not an AST: dynamic URLs and SDK-hidden HTTP need
  a directive or `@openshell ignore`. Planned: tree-sitter backend.
- JS regex literals are not parsed; Python docstrings are strings (directives must be `#` comments).
- Filesystem/process/landlock are startup-only in OpenShell; drift labels them `startup`.
- Runtime diff against deny logs (`diff-logs`) is not implemented in this prototype.
- Semantic checks mirror `openshell-policy::validate_sandbox_policy` (documented rules) but the authoritative
  validation is the gateway (`openshell sandbox create --policy`) and, soon, `openshell policy lint` (#4035).

## Develop

```
cargo test
```
