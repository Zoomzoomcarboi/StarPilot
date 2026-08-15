# RAVE Raylib Simulator

`tools/rave/rave_sim.py` is the canonical RAVE development simulator and control console. It reuses the production RAVE v1 pairing, HMAC, session, sequence/replay, and `RAVE_STATE` codec used by `rave_linkd`; there is no second test protocol and no Comma vehicle-state dependency.

The old silent stdin workflow has been replaced by a Raylib operator console with visible state, explicit controls, actionable recovery, and event logs. Headless mode remains available for automation.

## Quick start

From the active StarPilot checkout:

```bash
./tools/rave/launch_rave_sim.sh
```

Every normal launch first runs the in-process production-protocol self-test. The console opens only after pairing/session/state encode/decode passes.

The launcher uses the active checkout's prepared host runtime when available. If a rebased worktree does not yet have one, it can reuse a sibling `StarPilot-RAVE-*` host runtime for Python/generated dependencies while **always running the simulator source from the active checkout**. The selected source, Python, and runtime are printed at startup.

The dedicated link must already be configured:

- RAVE host / ZBook / Pi: `10.77.0.1/24`
- comma C3X: `10.77.0.2/24`
- runtime UDP: `47771`
- pairing UDP: `47772`

The simulator intentionally does not modify NetworkManager or network interfaces.

## Modes

### C3X NETWORK — default

This is the full-stack hardware path. The GUI receives comma-initiated pairing/session traffic on the dedicated Ethernet link and sends real authenticated `RAVE_STATE` traffic at 10 Hz.

```bash
./tools/rave/launch_rave_sim.sh
```

### LOCAL RAYLIB — desktop UI isolation

Publishes eligible `raveState` directly to the local message bus for desktop Raylib rendering tests. This bypasses Ethernet/auth **only for UI isolation** and is blocked on device hardware so it cannot create a second `raveState` publisher on a comma.

```bash
./tools/rave/launch_rave_sim.sh --local-ui
```

### HEADLESS — automation / terminal

```bash
./tools/rave/launch_rave_sim.sh --headless
```

### Protocol self-test only

```bash
./tools/rave/launch_rave_sim.sh --self-test
```

Expected:

```text
RAVE simulator self-test: PASS
```

## Raylib control console

The GUI exposes independent LEFT and RIGHT synthetic states and a live preview of what the C3X edge warning is expected to show.

Scenario controls:

- **WATCH** — side occupied + WATCH → static amber half-width edge warning.
- **WARNING** — side occupied + WARNING → static red full-width edge warning.
- **CLEAR** — side clear + no threat.
- **CLEAR BOTH SIDES** — clean baseline.
- **HEALTH OK / DEGRADED / FAULT** — validates the Gate 2C health gate. OK and DEGRADED are eligible; FAULT must fail dark.
- **PAUSE / RESUME** — manual transmission control.
- **STALE 600ms** — deterministic freshness test. TX pauses for 600 ms and automatically resumes. The C3X warning must clear by the 275 ms UI freshness limit.
- **RESTART** — rotates the simulated Pi session and visibly waits for a fresh comma challenge. Restart is no longer silent.

The status card shows network state, pairing phase, session state, health, left/right scenario, expected UI state, TX rate, last RX/TX age, packet counts, and error counters. A small edge-warning preview makes the simulator's intended output obvious before comparing against the C3X.

Protocol fault controls in C3X NETWORK mode:

- bad HMAC
- malformed datagram
- duplicate packet
- out-of-order sequence
- sequence reset
- old-session replay
- 32-packet authenticated burst

Keyboard shortcuts:

- `1 / 2 / 3` — left WATCH / WARNING / CLEAR
- `4 / 5 / 6` — right WATCH / WARNING / CLEAR
- `Space` — pause/resume
- `R` — restart simulated Pi session

## Pairing

Pairing remains **comma-initiated**, exactly like production. The simulator reports the handshake instead of silently waiting:

`WAITING → OFFER SENT → CONFIRM SENT → PAIRED`

A completed master key is persisted to `rave_pairing.json` with mode `0600`. Raw key material is never printed or included in logs.

`FORGET SIM KEY` is deliberately a two-click destructive action. If it is used, forget/re-pair the peer on the comma as well so both endpoints agree on credentials.

## Network recovery

A C3X reboot, cable interruption, temporarily missing `10.77.0.1`, or route loss no longer kills the simulator. Socket failures move the console to `RETRYING`; it attempts to bind again once per second and reports when the network recovers.

The simulator does not use `SO_REUSEADDR`, so accidentally launching a second instance cannot silently share the RAVE UDP ports. The second instance will visibly report the bind conflict instead of producing nondeterministic packet delivery.

## Logs

Each run creates a human-readable log and JSONL event log under:

```text
~/.local/state/rave-sim/
```

The active path is shown in the GUI. Logging is state/event based rather than packet-by-packet, so the normal 10 Hz stream does not flood the console or disk.

## Native Raylib Gate 2C path

The C3X Raylib UI now subscribes to the production `raveState` service directly. RAVE is explicitly excluded from generic UI `all_alive` / frequency / validity aggregate checks so loss of RAVE cannot turn into a generic UI/process-health dependency; RAVE applies its own fail-dark eligibility gate.

The warning is visible only when all Gate 2C conditions are true:

- a `raveState` message has actually been received
- message validity is true
- UI receipt age is `<= 275 ms`
- `packetAgeMs <= 275`
- RAVE is enabled
- peer is paired
- connection state is `connected`
- health is `ok` or `degraded`

Anything missing, stale, unknown, disconnected, or faulted produces no RAVE warning. Threat values outside NONE/WATCH/WARNING also fail to NONE. LEFT and RIGHT are independent and can be active simultaneously.

The renderer is native Raylib, runs in the existing onroad render path, and adds no UI network socket, Params polling loop, timer thread, or background worker.
