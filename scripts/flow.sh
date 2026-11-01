#!/usr/bin/env bash
# openshell-annotate-flow.sh - the whole policy-annotation flow for one repository.
#
#   scan -> generate -> lint -> drift -> schema/prover check -> (optional) sandbox run -> collect denies -> diff-logs (missing/stale directives)
#
# Run it on a machine that has the `openshell` CLI + a connected gateway, `openshell-prover`, docker (for --image), and a built
# `openshell-annotate` (https://github.com/ is NOT involved; it is the local ~/src/openshell-annotate crate). Nothing is pushed anywhere.
#
# Usage:
#   openshell-annotate-flow.sh REPO [--out DIR] [--bin PATH] [--deny-warnings]
#                                   [--image IMAGE [--run-seconds N] [--exercise FILE.js] [--cpu 2] [--memory 4Gi] [--env-from VAR]... [--keep] [--] CMD...]
#
#   REPO            repository root containing openshell-annotate.toml and the @openshell directives
#   --out DIR       output directory inside REPO (default: openshell) -> policy.yaml, providers.sh, flow-report.md, denies.txt
#   --image IMAGE   also run IMAGE in an OpenShell sandbox with the generated policy and report every DENIED connection
#   --env-from VAR  pass an environment variable from THIS shell into the sandbox (secrets never touch a file)
#   --exercise FILE a node script run inside the sandbox once it is Ready (`node -e`), to generate real traffic (use dummy credentials only)
#   --diff-logs F   skip the sandbox: only run diff-logs on an existing log file (shorthand or OCSF JSONL) and print the suggestions
#   --keep          do not delete the sandbox afterwards
#
# Exit status: 0 = clean; 1 = a check failed (see the report); 2 = usage / missing tool.
set -u
REPO="${1:-}"; [ -n "$REPO" ] && shift || { sed -n 2,20p "$0"; exit 2; }
OUT=openshell; BIN="${OPENSHELL_ANNOTATE:-$HOME/src/openshell-annotate/target/release/openshell-annotate}"
IMAGE=""; EXERCISE=""; DIFFLOGS=""; SECS=60; CPU=2; MEM=4Gi; KEEP=0; DENY_WARN=0; ENVFROM=(); CMD=()
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="$2"; shift;; --bin) BIN="$2"; shift;; --image) IMAGE="$2"; shift;; --run-seconds) SECS="$2"; shift;;
    --cpu) CPU="$2"; shift;; --memory) MEM="$2"; shift;; --env-from) ENVFROM+=(--env-from "$2"); shift;;
    --exercise) EXERCISE="$2"; shift;; --diff-logs) DIFFLOGS="$2"; shift;; --keep) KEEP=1;; --deny-warnings) DENY_WARN=1;; --) shift; CMD=("$@"); break;;
    *) echo "unknown option $1"; exit 2;;
  esac; shift
done
for t in "$BIN" ; do [ -x "$t" ] || { echo "missing openshell-annotate binary: $BIN"; exit 2; }; done
command -v openshell-prover >/dev/null || { echo "openshell-prover not found"; exit 2; }
cd "$REPO" || exit 2; mkdir -p "$OUT"
REPORT="$OUT/flow-report.md"; FAILED=0
step() { printf '\n## %s\n\n' "$1" >> "$REPORT"; echo "== $1"; }
code() { printf '```\n%s\n```\n' "$1" >> "$REPORT"; }
: > "$REPORT"; printf '# openshell-annotate flow report\n\nrepo: `%s`  \ntool: `%s`\n' "$(pwd)" "$("$BIN" --version 2>/dev/null)" >> "$REPORT"

step "scan"; o=$("$BIN" scan 2>&1); rc=$?; code "$(echo "$o" | tail -3)"; [ $rc -ne 0 ] && { echo "$o" | tail -5; FAILED=1; }
step "generate"; o=$("$BIN" generate -o "$OUT/policy.yaml" --providers-out "$OUT/providers.sh" 2>&1); rc=$?; code "$(echo "$o" | tail -8)"
[ $rc -ne 0 ] && { echo "$o" | tail -8; echo "generate failed: fix the directives (see report)"; FAILED=1; cat "$REPORT" | tail -3; exit 1; }
step "lint"; la=(lint --policy "$OUT/policy.yaml"); [ $DENY_WARN = 1 ] && la+=(--deny-warnings)
o=$("$BIN" "${la[@]}" 2>&1); rc=$?; code "$(echo "$o" | grep -v 'info\[exec\]' | tail -15)"; [ $rc -ne 0 ] && FAILED=1
step "drift"; o=$("$BIN" drift --policy "$OUT/policy.yaml" 2>&1); rc=$?; code "$(echo "$o" | tail -3)"; [ $rc -ne 0 ] && FAILED=1
step "schema / prover (openshell-policy-schema parse, boundary = itself)"
o=$(openshell-prover check --boundary "$OUT/policy.yaml" "$OUT/policy.yaml" 2>&1); rc=$?; code "$o"
{ [ $rc -eq 0 ] || { [ $rc -eq 3 ] && echo "$o" | grep -q '^result: unsupported'; }; } || FAILED=1

if [ -n "$DIFFLOGS" ]; then
  step "diff-logs ($DIFFLOGS)"; "$BIN" diff-logs "$DIFFLOGS" > "$OUT/diff-logs.txt" 2>&1; rc=$?; code "$(head -40 "$OUT/diff-logs.txt")"; [ $rc -ne 0 ] && FAILED=1
fi
if [ -n "$IMAGE" ]; then
  step "sandbox run ($IMAGE)"
  SB="flow-$(date +%H%M%S)"; SB="${SB:0:19}"
  openshell sandbox delete "$SB" >/dev/null 2>&1 </dev/null
  openshell sandbox create --name "$SB" --from "$IMAGE" --cpu "$CPU" --memory "$MEM" --policy "$OUT/policy.yaml" \
    --no-tty --no-auto-providers "${ENVFROM[@]}" -- "${CMD[@]:-sleep 3600}" > "$OUT/sandbox-create.log" 2>&1 </dev/null &
  ready=0; for _ in $(seq 1 90); do sleep 2
    st=$(openshell sandbox list </dev/null 2>/dev/null | awk -v n="$SB" '$1==n{print $NF}')
    [ "$st" = Ready ] && { ready=1; break; }; [ "$st" = Error ] && break; done
  if [ $ready = 1 ]; then
    echo "sandbox $SB ready; letting the workload run ${SECS}s (exercise it now: openshell sandbox exec -n $SB -- ... </dev/null)"; sleep "$SECS"
    [ -n "$EXERCISE" ] && { echo "exercising: $EXERCISE"; timeout 600 openshell sandbox exec -n "$SB" -- node -e "$(cat "$EXERCISE")" </dev/null > "$OUT/exercise.log" 2>&1; }
    sleep 6   # sandbox log delivery is batched: deny events lag by a few seconds
    openshell logs "$SB" --source sandbox -n 5000 </dev/null 2>&1 | sed 's/\x1b\[[0-9;]*m//g' > "$OUT/sandbox-logs.txt"
    grep -E 'DENIED' "$OUT/sandbox-logs.txt" > "$OUT/denies.txt"
    # unique (binary -> destination | reason) with counts: these are the gaps in the directives
    sed -nE 's/.*NET:OPEN \[[A-Z]+\] DENIED ([^ ]+) -> ([^ ]+) .*reason:([a-z_]+).*/\1 -> \2  (\3)/p; s/.*HTTP:([A-Z]+) \[[A-Z]+\] DENIED ([A-Z]+) ([^ ]+) .*/\2 \3  (l7)/p' "$OUT/denies.txt" | sort | uniq -c | sort -rn > "$OUT/denies-summary.txt"
    code "$(echo "denied: $(wc -l < "$OUT/denies.txt") events"; cat "$OUT/denies-summary.txt" | head -30)"
    step "diff-logs (denies -> directives; stale = never matched)"
    "$BIN" diff-logs "$OUT/sandbox-logs.txt" > "$OUT/diff-logs.txt" 2>&1; rc=$?; code "$(head -60 "$OUT/diff-logs.txt")"
    [ $rc -ne 0 ] && echo "diff-logs: suggestions exist (see $OUT/diff-logs.txt; apply with: $BIN diff-logs $OUT/sandbox-logs.txt --write)"
  else
    code "$(grep -iE 'error|×|│' "$OUT/sandbox-create.log" | head -8)"; FAILED=1
  fi
  [ $KEEP = 1 ] || openshell sandbox delete "$SB" </dev/null >/dev/null 2>&1
fi
echo; echo "report: $REPO/$REPORT   status: $([ $FAILED = 0 ] && echo clean || echo 'CHECK FAILED')"
[ $FAILED -eq 0 ]
