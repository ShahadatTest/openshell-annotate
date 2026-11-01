# openshell-annotate: hands-on testing walkthrough

Everything here is local to the dev server. Nothing is pushed, no remotes exist, no real secrets are used.
Verified end to end on 2026-11-01 (Asia/Jerusalem) on the dev server, OpenShell 0.1.6, `openshell-annotate 0.1.0`, from a fresh login shell.

| Section | What it proves | Measured time |
|---|---|---|
| 0. Prerequisites | tools + gateway are there | ~10 s |
| 1. Demo loop (`~/src/annotate-demo`) | lint -> annotate -> scan -> generate -> drift -> image -> sandbox -> deny -> diff-logs `--write` -> regenerate -> allowed | ~25 s with the image cached (measured full scripted loop); ~70 s the first time (45 s image build) |
| 1b. AI annotation (optional) | claude / cursor CLI adds the directives | ~1-3 min, needs your own CLI login |
| 2. Paperclip full flow | the real repo: 106 directives, 17 rules | static ~1 min; `--diff-logs` ~1 min; sandbox + exercise ~3 min |
| 3. Fixtures suite | 155 probes of the tool + real sandbox behaviour | static 7 s; `--sandbox` ~2 min |
| 4. Cleanup | nothing left running | ~5 s |

## 0. Prerequisites check

SSH in and use a **login shell**: `~/.local/bin` (where `openshell-annotate` is installed) is on PATH in login shells only. A plain
`ssh host 'cmd'` does not have it; use `ssh -t user@dev-server` interactively, or `ssh user@dev-server 'bash -lc "cmd"'`.

```bash
ssh user@dev-server
```

```bash
openshell-annotate --version            # openshell-annotate 0.1.0
openshell --version                     # openshell 0.1.6
command -v openshell-prover jq docker   # all three print a path
openshell sandbox list </dev/null       # "No sandboxes found." (or a list): proves the gateway answers
docker image inspect paperclip-openshell:local fx-probe:local >/dev/null && echo "images ok"   # only needed for sections 2 and 3
```

If `openshell-annotate` is missing, rebuild and reinstall (about 1 min, offline-capable once the crates are cached):

```bash
cd ~/src/openshell-annotate && cargo build --release && install -m 755 target/release/openshell-annotate ~/.local/bin/
cargo test                               # 56 tests, ~3 s
```

## 1. The demo loop, from zero

The demo repo is `~/src/annotate-demo`: `app/weather.py` (urllib GET + a file write to `/data`), `app/notify.js` (fetch) and
`app/telemetry.js` (node `https.get`), a 3-line Dockerfile (Ubuntu + python3 + nodejs, ~220 MB) and `openshell-annotate.toml`
with the real interpreter paths. It is a git repo with no remote; start every run from a clean tree:

```bash
cd ~/src/annotate-demo
scripts/reset.sh                         # "demo reset to the last commit"; also deletes a leftover demo sandbox
git status --short                       # empty
```

### 1.1 Lint: see what is missing

```bash
openshell-annotate lint
```

Expected (5 warnings, exit code 0; `--deny-warnings` makes it 1):

```
app/notify.js:3: warning[net]: fetch() without an @openshell directive (suggest: @openshell egress api.github.com:443 reason="...")
app/telemetry.js:3: warning[net]: node http(s) request without an @openshell directive (suggest: @openshell egress example.org:443 reason="...")
app/weather.py:8: warning[net]: urllib without an @openshell directive (suggest: @openshell egress api.open-meteo.com:443 reason="...")
app/weather.py:12: warning[fs]: filesystem write (os.makedirs) to /data, which is outside the sandbox baseline (/tmp) and every declared fs write root (...)
app/weather.py:13: warning[fs]: open() for writing to /data/report.json, which is outside ...
lint: 1 directive(s); 0 error(s), 5 warning(s), 1 info
```

(The 1 directive is the `process` line in the Dockerfile.)

### 1.2 Annotate: by hand (default path)

A directive is a comment on the line above the call: `// @openshell egress HOST:PORT reason="..."` (JS/Go),
`# @openshell ...` (Python/shell). Other kinds: `fs read|write PATH`, `provider ENV_VAR`, `bin`, `process`, `ignore`.
You can edit the files yourself, or run the script that does what you would do for **two of the three** calls
(it deliberately leaves `app/telemetry.js` alone: that is the call you "forgot", and the sandbox will catch it in 1.7):

```bash
scripts/annotate-by-hand.sh
```

```
 app/notify.js  | 1 +
 app/weather.py | 2 ++
```

```bash
openshell-annotate lint                  # only telemetry.js is left: 1 warning
```

### 1.2b Annotate: with an AI CLI (optional alternative)

See section 1b. It is a replacement for 1.2 (it would annotate all three calls, so the deny in 1.7 will not happen; run
`scripts/reset.sh` and do 1.2 by hand if you want to see the deny).

### 1.3 Scan: what directives does the tool see?

```bash
openshell-annotate scan
```

```
Dockerfile:11  process   # the sandbox rejects root; uid 1000 owns /data
app/notify.js:3  egress api.github.com:443  # zen line
app/weather.py:8  egress api.open-meteo.com:443  # current weather
app/weather.py:14  fs write /data  # keeps the raw API answer
4 directive(s) in 4 file(s)
```

### 1.4 Generate the policy, then check drift and the prover

```bash
mkdir -p openshell
openshell-annotate generate -o openshell/policy.yaml --providers-out openshell/providers.sh
# generated: 4 directive(s) -> 2 network rule(s), 2 endpoint(s), 2 binary path(s), fs read 0 / write 1, 0 provider(s) (0 unmapped)
openshell-annotate drift --policy openshell/policy.yaml
# no drift: openshell/policy.yaml matches 4 directive(s)
openshell-prover check --boundary openshell/policy.yaml openshell/policy.yaml | tail -2
# result: within_boundary
cat openshell/policy.yaml                # every entry has its reason and file:line as a comment
```

`openshell/` is git-ignored in the demo (it is generated output). In a real repo you commit `policy.yaml` and let CI run `drift`.

### 1.5 Build the tiny image

```bash
scripts/build-image.sh
```

```
ok   /usr/bin/node is a real executable
ok   /usr/bin/python3.12 is a real executable
ok   /usr/bin/bash is a real executable
image annotate-demo:local ready (218 MB)
```

(~45 s the first time, ~2 s when cached. The script also checks that the interpreter paths in `openshell-annotate.toml`
are real files, not symlinks: OpenShell matches the resolved binary path.)

### 1.6 Run it in an OpenShell sandbox with the policy

```bash
scripts/sandbox-run.sh
```

It creates sandbox `annotate-demo`, waits for Ready, runs the three programs with `openshell sandbox exec`, waits 6 s for the
batched log delivery, saves `demo-out/sandbox-logs.txt`, prints the decisions and deletes the sandbox (`--keep` leaves it).
Expected (~10 s):

```
sandbox annotate-demo is Ready
--- python3 /usr/local/share/demo/weather.py
    weather: 26.0 C -> /data/report.json
--- node /usr/local/share/demo/notify.js
    zen: 200 Responsive is better than fast.
--- node /usr/local/share/demo/telemetry.js
    telemetry failed: connect EACCES 198.18.0.4:443 - Local (0.0.0.0:0)
--- policy decisions (demo-out/sandbox-logs.txt)
  HTTP:GET [INFO] ALLOWED GET https://api.github.com/zen [policy:api_github_com engine:l7]
  HTTP:GET [INFO] ALLOWED GET https://api.open-meteo.com/v1/forecast [policy:api_open_meteo_com engine:l7]
  NET:OPEN [INFO] ALLOWED /usr/bin/node(0) -> api.github.com:443 [policy:api_github_com engine:opa]
  NET:OPEN [INFO] ALLOWED /usr/bin/python3.12(0) -> api.open-meteo.com:443 [policy:api_open_meteo_com engine:opa]
  NET:OPEN [MED] DENIED /usr/bin/node(0) -> example.org:443 [reason:transparent_tcp_policy_denied]
```

The file write to `/data` worked because of the `fs write /data` directive (Landlock). The weather numbers will differ.

### 1.7 The deny, and diff-logs

The `DENIED ... example.org:443` line above is the deny (the call whose directive you "forgot"). Turn it into a fix:

```bash
openshell-annotate diff-logs demo-out/sandbox-logs.txt
```

```
diff-logs: 5 event(s) (1 denied, 4 allowed); 1 suggestion(s), 0 stale directive(s)
note: logs are best-effort and lossy; absence of an event is not proof. Filesystem denials are not logged by OpenShell 0.1.6 (#4270).

MISSING_EGRESS   example.org:443 x1 /usr/bin/node
  no directive covers this host:port
  suggest: @openshell egress example.org:443 reason="observed in sandbox log: /usr/bin/node (confirm it is needed)" bin=/usr/bin/node
  place:   app/telemetry.js:4
```

(exit code 1 = there are suggestions; 0 = clean). Now let it write the directive into the source, above the line that mentions the host:

```bash
openshell-annotate diff-logs demo-out/sandbox-logs.txt --write
git diff app/telemetry.js
```

```
   https
+  // @openshell egress example.org:443 reason="observed in sandbox log: /usr/bin/node (confirm it is needed)" bin=/usr/bin/node
   .get("https://example.org/", ...
```

Edit the `reason` to say why you really need the host (that text ends up in the policy). `--write` falls back to
`openshell/observed-egress.sh` when it cannot find the host in any source file.

### 1.8 Regenerate and prove the loop is closed

```bash
openshell-annotate lint                  # 5 directive(s); 0 error(s), 0 warning(s)
openshell-annotate drift --policy openshell/policy.yaml
# missing [live] network_policies example_org: endpoints {"example.org:[443]"}    <- the old policy is stale: expected
openshell-annotate generate -o openshell/policy.yaml --providers-out openshell/providers.sh
# generated: 5 directive(s) -> 3 network rule(s) ...
openshell-annotate drift --policy openshell/policy.yaml     # no drift
scripts/sandbox-run.sh                   # telemetry.js now prints "telemetry: 200"; all decisions ALLOWED
openshell-annotate diff-logs demo-out/sandbox-logs.txt      # "6 event(s) (0 denied, 6 allowed); 0 suggestion(s)" exit 0
```

Loop done. To run it again from zero: `scripts/reset.sh`.

## 1b. AI annotation with the claude or cursor CLI (optional)

`scripts/ai-annotate.sh` gives the CLI the `annotate-openshell-policy` skill that ships with the tool
(`skills/annotate-openshell-policy/SKILL.md`: how to choose binaries, reasons, scopes, when to use `ignore`), limits it to
reading/editing files and running `openshell-annotate`, and ends with a lint.

```bash
cd ~/src/annotate-demo && scripts/reset.sh
scripts/ai-annotate.sh            # Claude Code: claude -p ... --append-system-prompt "$(cat SKILL.md)" --permission-mode acceptEdits --allowedTools Read Edit "Bash(openshell-annotate:*)"
scripts/ai-annotate.sh cursor     # Cursor CLI: cursor-agent -p --force "<skill text> TASK: ..."
git diff                          # review what it wrote: one directive + a real reason above every call/write
openshell-annotate lint           # expect 0 warnings; then continue with 1.3
```

* **claude**: installed at `~/.local/bin/claude` (2.1.299). **When I tested, `claude auth status` said you were logged in with claude.ai, but
  a real call failed with "OAuth session expired and could not be refreshed". Run `claude` once interactively and `/login`** before
  using this step. I did not run the AI step to completion, so its output is unverified.
* **cursor**: no `cursor-agent` on the dev server. Install with `curl https://cursor.com/install -fsS | bash`, then `cursor-agent login`.
  The `cursor` branch of the script uses the documented headless flags (`-p`, `--force`) but is untested.
* Same idea in any other agent: point it at `skills/annotate-openshell-policy/SKILL.md` (also summarised in `AGENTS.md`)
  and tell it to finish when `openshell-annotate lint` is clean.

## 2. Paperclip: the full flow on a real repository

`~/src/paperclip` (local branch `openshell-directives`, no remote) has 106 directives. `scripts/flow.sh` runs
scan -> generate -> lint -> drift -> prover and optionally a sandbox run + diff-logs. It writes `openshell/policy.yaml`,
`providers.sh` and `flow-report.md` in the repo.

```bash
cd ~/src/paperclip
git status --short                                  # clean
~/src/openshell-annotate/scripts/flow.sh .          # static checks only, ~1 min (scan 11 s, lint 16 s, generate 11 s)
```

```
== scan
== generate
== lint
== drift
== schema / prover (openshell-policy-schema parse, boundary = itself)

report: ./openshell/flow-report.md   status: clean
```

Key lines of `openshell/flow-report.md`: `lint: 106 directive(s); 0 error(s), 0 warning(s), 238 info`,
`no drift: openshell/policy.yaml matches 106 directive(s)`, `result: within_boundary`. (The 238 infos are the
"URL literal without matching egress" hints for code that is excluded from the sandbox runtime; the 9 generate-time warnings
about "duplicates a provider profile endpoint" are informational.)

### 2.1 diff-logs against recorded logs (no sandbox)

```bash
~/src/openshell-annotate/scripts/flow.sh . --diff-logs openshell/observed-sandbox-logs.txt   # ~1 min
tail -20 openshell/diff-logs.txt
```

Expected: `status: clean`; the diff output lists `STALE` directives (hosts nothing in that log touched: codex, discord, slack,
agentmail ...) and one `DECLINED  http-intake.logs.us5.datadoghq.com:443` (the claude CLI telemetry host, intentionally ignored),
and **0 suggestions**.

### 2.2 Real sandbox run, exercised with dummy credentials (~3 min)

Throwaway/dummy values only; they are passed with `--env-from` so they never touch a file:

```bash
cd ~/src/paperclip
export BETTER_AUTH_SECRET=throwaway-demo-secret-0000000000000000 PAPERCLIP_DEPLOYMENT_MODE=local_trusted HOST=127.0.0.1 \
       ANTHROPIC_API_KEY=sk-ant-dummy-not-a-real-key GH_TOKEN=ghp_dummy0000000000000000000000000000
~/src/openshell-annotate/scripts/flow.sh . --image paperclip-openshell:local --run-seconds 45 \
  --exercise openshell/exercise/agents-and-github.js \
  --env-from BETTER_AUTH_SECRET --env-from PAPERCLIP_DEPLOYMENT_MODE --env-from HOST --env-from ANTHROPIC_API_KEY --env-from GH_TOKEN \
  -- sh -c "cd /app && exec node --import ./server/node_modules/tsx/dist/loader.mjs server/dist/index.js"
```

(`paperclip-openshell:local` is the published Paperclip image plus a 2-line overlay; the server must be started from `/app`.
The sandbox is named `flow-HHMMSS` and deleted at the end; add `--keep` to inspect it.) Expected tail:

```
== sandbox run (paperclip-openshell:local)
sandbox flow-090043 ready; letting the workload run 45s ...
exercising: openshell/exercise/agents-and-github.js
== diff-logs (denies -> directives; stale = never matched)

report: ./openshell/flow-report.md   status: clean
```

Look at what happened:

```bash
head -5 openshell/exercise.log          # GET /health 200 ..., POST /companies 201 ..., agents created
cat openshell/denies-summary.txt        # the denied connections (may be empty or just the datadog host, which is declined)
cat openshell/diff-logs.txt             # 0 suggestions; STALE for hosts the dummy-credential run cannot reach; DECLINED datadog
```

The other driver, `openshell/exercise/chat-endpoints.js`, needs an *active* agent, which needs a real LLM credential (see "What needs real keys").
The run leaves generated files in `openshell/` (logs, denies, `exercise.log`, `sandbox-create.log`); they are not part of the repo,
remove with `git -C ~/src/paperclip checkout -- openshell && git -C ~/src/paperclip clean -fdq openshell`.

## 3. The fixtures suite

`~/src/openshell-annotate-fixtures` has 40+ cases (scan/generate/lint/drift/diff-logs/profile/prover) and, with `--sandbox`,
real sandbox probes of allowed and denied traffic, filesystem and binary-identity behaviour.

```bash
cd ~/src/openshell-annotate-fixtures
./run-tests.sh                           # static, ~7 s       -> summary: pass=116 fail=0 skip=0
./run-tests.sh --sandbox                 # + real sandboxes, ~2 min (uses fx-probe:local) -> summary: pass=155 fail=0 skip=0
./run-tests.sh --sandbox --filter difflogs   # a subset by case name (see: ls cases)
./run-tests.sh --update                  # re-bless expected files after an intended tool change (review the git diff!)
```

Results land in `results/last-run.tsv` (tracked) and `results/logs-*.txt`. It uses `openshell-annotate` from PATH
(falls back to `~/src/openshell-annotate/target/release/`).

## 4. Cleanup

```bash
openshell sandbox list </dev/null                       # normally "No sandboxes found."
for s in $(openshell sandbox list </dev/null 2>/dev/null | awk 'NR>1 && /^(annotate-demo|flow-|fx-)/{print $1}'); do openshell sandbox delete "$s" </dev/null; done
cd ~/src/annotate-demo && scripts/reset.sh              # pristine demo, removes demo-out/ and openshell/
cd ~/src/paperclip && git checkout -- openshell && git clean -fdq openshell
cd ~/src/openshell-annotate-fixtures && git checkout -- results
docker rmi annotate-demo:local                          # optional (~220 MB); keep paperclip-openshell:local and fx-probe:local (9 GB each, slow to rebuild)
```

## 5. What needs real keys (all optional)

| Flow | Needs |
|---|---|
| 1b AI annotation | your own `claude` login (`claude`, then `/login`; the saved session had expired), or `cursor-agent` installed + logged in |
| Paperclip codex agent | a ChatGPT login or a real `OPENAI_API_KEY` bound to the agent |
| Paperclip Slack / Discord / GitHub chat endpoints (`chat-endpoints.js`) | real tokens plus an *active* agent (a working LLM key) |
| Anything that asks for a key in sections 0-4 | nothing: the demo, flow `--diff-logs`, the dummy-credential run and the fixtures need no secret |

Never put real keys in files; use `--env-from VAR`.

## 6. Troubleshooting

* **`openshell-annotate: command not found` over ssh**: non-login shell. Use `bash -lc '...'` or `export PATH=$HOME/.local/bin:$PATH`.
* **Deny seen but `openshell logs` shows nothing**: log delivery to the gateway is batched; wait 5-6 s after the traffic, and use
  `-n 5000` (the default tail is short). The scripts do both. Always run `openshell` commands that are not meant to read stdin with
  `</dev/null` (inside heredocs and scripts they otherwise swallow the rest of the script).
* **Sandbox name too long**: names are limited to 19 characters.
* **Sandbox stuck in `Provisioning`/`Error`**: `tail demo-out/sandbox-create.log`; typical causes: OCI `WORKDIR` not usable by uid 1000
  (the image needs a `WORKDIR` the sandbox user owns and a numeric `USER`, root is rejected), or the gateway is not running (`openshell sandbox list`).
* **Landlock (filesystem) notes**: `filesystem_policy` and `process` are startup-only: change them and recreate the sandbox
  (network rules are live). When a network rule exists the supervisor adds a baseline: read `/usr /lib /etc /proc /dev/urandom`,
  write `/tmp /dev/null`; `/app` and `/opt` are *not* included, so keep app code under `/usr/local/share` or declare `fs read`.
  Filesystem denials are **not logged** (OpenShell #4270): a Landlock deny shows up only as `EACCES` in the app's own output.
  Landlock also denies `open("/")` even with `fs read /`; apps that fsync every ancestor up to `/` (Paperclip's
  `ensureDurableDirectory`) fail on agent runs and need an app change; no policy fixes it.
* **DNS notes**: transparent TCP interception only works for protocols where the client speaks first (TLS/HTTP). A host that is
  not DNS-eligible shows `NET:REFUSE ... policy_dns_ineligible` with no binary. A TLS client that gets
  `connect EACCES 198.18.0.x:443` was denied by policy (`transparent_tcp_policy_denied`), the `198.18.x` address is the proxy's placeholder.
* **Allowed in the policy but still `DENIED ... binary not in rule`**: the rule's `binaries` must be the real executable that opens
  the connection (`/usr/bin/node`, not a script or a symlink such as `/usr/bin/python3`). Ancestors count: `git-remote-http` is allowed under `git`.
* **`diff-logs --write` put the directive on the wrong line**: it inserts above the first source line that mentions the host; move it
  next to the call if the host literal lives in a config constant, or use `@openshell egress ... host=` and `ignore` as needed.
* **`lint` warns about a test driver / tool script**: add `@openshell ignore kind=net scope=file reason="..."` at the top of the file, or put
  the path in `[scan] exclude` / `[lint] exclude` in `openshell-annotate.toml`.
* **A directive is not in `scan` output**: scan lists exactly what the tool parses. Directive must be the first thing in a comment.
  (Fixed on 2026-11-01: for JS/TS the comments now come from the syntax tree; before, a regex literal with a stray quote could hide
  all directives below it in a big file.)
* **Docker image is huge / rebuild is slow**: `paperclip-openshell:local` and `fx-probe:local` are ~9 GB because the Paperclip image is; do not delete them.
