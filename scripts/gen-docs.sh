#!/usr/bin/env bash
# Regenerate docs/CLI.md and docs/DIRECTIVES.md from the code. `--check` only verifies they are current.
set -euo pipefail
cd "$(dirname "$0")/.."
exec cargo run --quiet -- docs --out docs "$@"
