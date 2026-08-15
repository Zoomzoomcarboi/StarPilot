#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "$REPO_ROOT" || ! -f "$REPO_ROOT/tools/rave/rave_sim.py" ]]; then
  echo "ERROR: run this launcher from a StarPilot checkout containing tools/rave/rave_sim.py" >&2
  exit 2
fi

choose_runtime() {
  local candidate

  if [[ -n "${RAVE_SIM_PYTHON:-}" ]]; then
    echo "$RAVE_SIM_PYTHON|${RAVE_SIM_RUNTIME_ROOT:-$REPO_ROOT}"
    return 0
  fi

  if [[ -n "${RAVE_SIM_RUNTIME_ROOT:-}" ]]; then
    candidate="$RAVE_SIM_RUNTIME_ROOT"
    if [[ -x "$candidate/venv/bin/python3" && -d "$candidate/worktree" ]]; then
      echo "$candidate/venv/bin/python3|$candidate/worktree"
      return 0
    fi
    if [[ -x "$candidate/.host_runtime/linux/venv/bin/python3" && -d "$candidate/.host_runtime/linux/worktree" ]]; then
      echo "$candidate/.host_runtime/linux/venv/bin/python3|$candidate/.host_runtime/linux/worktree"
      return 0
    fi
    echo "ERROR: RAVE_SIM_RUNTIME_ROOT is set but is not a prepared host runtime: $candidate" >&2
    return 1
  fi

  candidate="$REPO_ROOT/.host_runtime/linux"
  if [[ -x "$candidate/venv/bin/python3" && -d "$candidate/worktree" ]]; then
    echo "$candidate/venv/bin/python3|$candidate/worktree"
    return 0
  fi

  # A rebased worktree may intentionally reuse a previously prepared host runtime.
  # The simulator source always comes from REPO_ROOT; only Python/generated deps
  # come from the runtime selected here.
  shopt -s nullglob
  for candidate in "$HOME"/StarPilot-RAVE-*/.host_runtime/linux; do
    if [[ -x "$candidate/venv/bin/python3" && -d "$candidate/worktree" ]]; then
      echo "$candidate/venv/bin/python3|$candidate/worktree"
      shopt -u nullglob
      return 0
    fi
  done
  shopt -u nullglob

  if command -v python3 >/dev/null 2>&1; then
    echo "$(command -v python3)|$REPO_ROOT"
    return 0
  fi
  return 1
}

runtime="$(choose_runtime || true)"
if [[ -z "$runtime" ]]; then
  echo "ERROR: no usable Python/StarPilot host runtime found." >&2
  echo "Prepare the desktop host runtime or set RAVE_SIM_PYTHON / RAVE_SIM_RUNTIME_ROOT." >&2
  exit 3
fi

PYTHON_BIN="${runtime%%|*}"
RUNTIME_ROOT="${runtime#*|}"

NEEDS_PYRAY=1
for arg in "$@"; do
  if [[ "$arg" == "--headless" || "$arg" == "--self-test" ]]; then
    NEEDS_PYRAY=0
  fi
done

if (( NEEDS_PYRAY )); then
  if ! "$PYTHON_BIN" - <<'PY' >/dev/null 2>&1
import pyray
PY
  then
    echo "ERROR: $PYTHON_BIN does not provide pyray." >&2
    echo "Use the prepared StarPilot host runtime or pass --headless." >&2
    exit 4
  fi
fi

export PYTHONPATH="$RUNTIME_ROOT:$RUNTIME_ROOT/starpilot/third_party${PYTHONPATH:+:$PYTHONPATH}"

SIM_SOURCE="$REPO_ROOT/tools/rave/rave_sim.py"

echo "RAVE Simulator"
echo "  source:  $SIM_SOURCE"
echo "  python:  $PYTHON_BIN"
echo "  runtime: $RUNTIME_ROOT"
echo

# Every normal launch proves the selected runtime still agrees with the RAVE
# pairing/session/state protocol before opening the operator console.
if [[ " ${*:-} " != *" --self-test "* ]]; then
  "$PYTHON_BIN" -u "$SIM_SOURCE" --self-test
  echo
fi

exec "$PYTHON_BIN" -u "$SIM_SOURCE" "$@"
