# AGENTS.md — RAVE Engineering Contract

This repository contains **RAVE — Rear Awareness Vision Engine** integrated into StarPilot/Aether/openpilot.

RAVE is safety-sensitive development. Component-level validation, successful simulator runs, or a working C3X UI do **not** by themselves make the complete system road-ready or production-ready. Never describe a capability as hardware-validated, release-qualified, or production-ready unless the corresponding hardware/vehicle acceptance work has actually been completed.

This file is the engineering contract for RAVE work. It exists so lessons learned stay learned, safety invariants are not rediscovered through regressions, and coding agents do not repeatedly introduce bugs that have already been diagnosed and fixed.

**Before changing RAVE code, read this file.** If a requested change conflicts with a rule here, stop and surface the conflict instead of silently changing the architecture. A newer explicit project decision may supersede a rule, but the change should be documented here at the same time.

---

## 1. Priority order

RAVE decisions follow this order:

1. Safety.
2. Low end-to-end latency and low frame age.
3. Deterministic behavior.
4. Reliability and graceful failure.
5. Raspberry Pi 5 performance headroom.
6. Clear, usable UI/UX.
7. Feature richness.

If a feature conflicts with a higher-priority item, the feature loses.

Do not trade safety, latency, or reliability for model complexity, nominal FPS, visual flair, convenience, or feature count.

---

## 2. Raspberry Pi 5 is the hard production target

The Raspberry Pi 5 is the hard target platform for RAVE.

Every perception, tracking, temporal, networking, and support feature must be designed to fit the Pi 5 real-time performance envelope **from the beginning**.

Required rules:

- Do not build a heavy feature first and plan to optimize it later.
- Preserve compute headroom for future features and worst-case conditions.
- Prefer low frame age over impressive average FPS.
- Drop stale frames rather than queueing them.
- Never allow processing queues to grow unbounded.
- Camera capture may run faster than inference; that is expected.
- Current design intent is a 60 FPS camera source with inference capped as needed around 30 FPS.
- Only add more expensive temporal models, transformers, GRUs, larger detectors, or additional processing if measured Pi 5 headroom remains available.
- Performance claims must ultimately be validated on Pi 5 hardware, not inferred from desktop/ZBook performance.

A feature that works well on a desktop GPU but cannot meet the Pi 5 latency envelope is not a production-ready RAVE feature.

---

## 3. Architectural boundary: Pi does RAVE intelligence, C3X stays lightweight

The comma C3X is **not** the RAVE perception computer.

The Pi-side endpoint owns:

- Camera ingest.
- Object detection.
- Vehicle/motorcycle tracking.
- Temporal state estimation.
- Danger-zone logic.
- Threat classification.

The C3X should remain a lightweight authenticated receive/display endpoint.

### Core invariant

**Normal comma / StarPilot / openpilot operation must never depend on RAVE being present, connected, paired, alive, or healthy.**

Loss of RAVE must only remove RAVE information. It must not create a generic openpilot fault, controls fault, communication fault, or degraded vehicle-control state.

### Hard vehicle-control trust boundary

RAVE is an **advisory rear-awareness system**, not a vehicle-control authority.

- The Pi must have no Panda or vehicle-CAN interfaces, libraries, dependencies, credentials, permissions, or code paths.
- The Pi must never send steering, braking, acceleration, cruise, or other vehicle-control commands.
- The C3X receiver/UI must never translate RAVE metadata directly into Panda/CAN or vehicle-control commands.
- RAVE may inform the driver through the reviewed UI contract; it must not silently become an actuator path.
- The external RAVE computer must be able to disappear, reboot, lose power, lose Ethernet, or fail authentication without preventing normal StarPilot/openpilot operation.
- Keep the Pi -> C3X data contract minimal: authenticated health/availability and already-determined RAVE state/threat metadata. Do not move perception reasoning onto the C3X for convenience.

---

## 4. Preserve the validated RX-only runtime architecture

The known-good runtime architecture intentionally removed continuous Comma -> Pi vehicle-state traffic after it was proven to be the source of the original RAVE-related `commIssue`.

Do not reintroduce the removed runtime path casually.

Explicitly prohibited without a deliberate architecture review and full hardware revalidation:

- `SubMaster(["carState"])` inside `rave_linkd` for runtime telemetry.
- Continuous `sm.update()` in `rave_linkd` for Comma -> Pi vehicle-state transmission.
- 50 Hz `VEHICLE_STATE` transmission from comma to Pi.
- Dependence on comma vehicle state for core RAVE perception or threat classification.
- New continuous high-rate Comma -> Pi telemetry simply because it is convenient.

The validated RX-only design reports:

`vehicleStateTxHz = 0.0`

Preserve that invariant.

The dormant `VEHICLE_STATE` wire enum/codec may remain for compatibility even though the production runtime path is disabled. Do not interpret its presence as permission to start transmitting it again.

Protocol message IDs, existing field meanings, and protocol-version semantics are compatibility boundaries. Do not renumber, reuse, or silently reinterpret them. Any intentional wire-contract change requires explicit compatibility review and end-to-end protocol tests.

Do not touch controls, Panda safety, CAN actuation, longitudinal planning, or lateral planning for normal RAVE UI/perception work.

---

## 5. RAVE must never recreate the original commIssue failure mode

A major lesson learned is that a RAVE process or service must not become part of generic openpilot process-health dependency in a way that can fault the vehicle stack.

Required behavior:

- The UI may subscribe to `raveState`.
- Missing RAVE data must not cause a generic `commIssue`.
- Stale RAVE data must not cause a generic `commIssue`.
- Invalid RAVE data must not cause a generic `commIssue`.
- Unplugging Ethernet must not create a StarPilot/openpilot communication fault.
- Killing the Pi-side endpoint must not create a StarPilot/openpilot communication fault.
- RAVE being disabled must return the system to normal StarPilot behavior.
- RAVE service health must not be added to broad all-services health aggregation in a way that makes normal vehicle operation depend on RAVE.

Any change that violates this is a regression even if RAVE itself appears to work.

---

## 6. Strict fail-dark warning semantics

RAVE warnings are advisory UI information. If the data cannot be trusted, render **no RAVE warning**.

A RAVE warning is eligible only when **every** condition below is true:

- A `raveState` message has actually been received.
- The message is valid.
- Local receipt age is <= **275 ms**.
- `packetAgeMs` is <= **275 ms**.
- RAVE is enabled.
- RAVE is paired.
- Connection state is `CONNECTED`.
- Health is `OK` or `DEGRADED`.

Anything else must render no RAVE warning.

Fail-dark conditions include:

- No message.
- Invalid message.
- Local stale receipt.
- `packetAgeMs > 275`.
- RAVE disabled.
- Not paired.
- Pairing in progress.
- Waiting for authenticated session.
- Connection stale.
- Connection error.
- Health `UNKNOWN`.
- Health `FAULT`.
- Authentication loss.
- Pi restart before session re-establishment.
- Cable unplug.
- Endpoint process death.
- Malformed packet.
- Replay rejection.
- Duplicate rejection.
- Out-of-order rejection.

Do not hold the previous warning through an untrusted state. Unknown does not mean occupied; unknown means no RAVE visual assertion.

### Freshness clocks and authenticated session identity

Cross-device monotonic clocks are **not comparable**.

- Never compare a Pi monotonic timestamp directly with the C3X monotonic clock to decide freshness.
- Receiver-local arrival time is the authoritative freshness clock on the C3X.
- Sender timestamps may describe ordering or sender-side processing age within one authenticated boot/session; they are not proof of receiver freshness.
- Persistent device identity and ephemeral boot/session identity are separate concepts.
- A new boot/session identifier may reset receiver state only after that session transition has been authenticated.
- Validate protocol version, message type/size, data ranges, session binding, sequence/replay state, and authenticated identity before trusting payload state.

### Threat ownership stays on the RAVE computer

Once a `raveState` message passes the eligibility checks above, `leftThreat` and `rightThreat` are the reviewed warning inputs.

- Do not require factory blind-spot state as a prerequisite for a RAVE warning.
- Do not require `LaneState.OCCUPIED` as an additional UI gate unless the architecture is deliberately changed and revalidated.
- Do not use C3X turn-signal state to upgrade WATCH to WARNING.
- Do not recreate the removed Comma -> Pi state dependency indirectly in the UI.
- Lane state may remain useful context/telemetry, but the external RAVE computer owns danger/threat determination.

---

## 7. Warning visual contract

Gate 2C warning presentation is intentionally simple and static.

- `NONE` -> no RAVE border.
- `WATCH` -> static amber warning on the relevant side.
- `WARNING` -> static red warning on the relevant side.
- Left and right sides are independent.
- Left and right may display simultaneously.
- WATCH uses approximately half the normal warning border width.
- WARNING uses the full warning border width.

Do not add flashing, pulsing, animations, countdowns, distracting text, or sound without a separate reviewed safety decision.

Do not add new UI timers solely to animate RAVE warnings.

Do not log warning state every frame.

---

## 8. Raylib is the active production C3X UI

Current Firestar/StarPilot uses the Python/Raylib UI path on C3X.

New RAVE production UI behavior must target Raylib.

The old Qt implementation may be used as a behavioral reference, but do not assume Qt code is active on the device.

Raylib integration rules:

- Use native StarPilot/Aether Raylib controls, styling, layout, and lifecycle. Do not add a second UI framework for RAVE.
- Use the existing shared UI `SubMaster`; do not create a dedicated RAVE polling thread in the UI.
- Isolate `raveState` from generic all-services health/frequency/validity aggregation so RAVE cannot become a vehicle-stack dependency.
- Avoid per-frame Params reads.
- Do not perform network I/O in the UI process.
- Do not call NetworkManager D-Bus or `nmcli` from the UI.
- Do not add sleeps, blocking operations, subprocess waits, or long work to render/update callbacks.
- Do not leak detached/polling threads or resources across layout changes.
- Keep RAVE eligibility logic cheap and deterministic.
- Use the existing StarPilot border/render architecture where practical.
- Critical full openpilot alerts take precedence over advisory RAVE visuals.
- Never retain a stale `Connected` presentation after backend state changes.
- Avoid duplicate actions, contradictory state booleans, and malformed-Params crash paths.
- Unsafe network/pairing/configuration changes must not become available onroad.
- A RAVE settings action must never crash or restart the Raylib UI.
- There should be one canonical production RAVE warning implementation, not parallel Qt and Raylib implementations that can diverge.

---

## 9. Pairing and security are real safety boundaries

Do not weaken the existing RAVE security model to make development easier.

Preserve:

- Persistent peer ID.
- Persistent peer name.
- 32-byte master key.
- HMAC authentication.
- Directional session keys.
- Challenge/ACK session establishment.
- Session binding.
- Sequence checking.
- Replay rejection.
- Duplicate/out-of-order rejection.
- Malformed/authentication counters.
- Bounded receive drain.

Pairing is allowed only when the comma is unambiguously offroad.

`Enable RAVE` and `Pair Device` are separate concepts and must remain separate in the UI.

Correct pairing UX:

1. User requests pairing while offroad.
2. Existing `RavePairRequest` starts the pairing window.
3. UI shows a searching/pairing state.
4. A discovered candidate is shown to the user.
5. User explicitly confirms the candidate.
6. Existing `RavePairConfirm` performs key installation.
7. Successful authenticated confirmation persists the peer ID/name/key.
8. Cancel and Forget are explicit operations.

Do not auto-confirm a candidate merely because only one device answered.

The pairing command path is intentionally split between persistent and transient state:

- `RavePeerId`, `RavePeerName`, and `RavePairingKey` are persistent credentials.
- `RavePairRequest`, `RavePairConfirm`, `RavePairCancel`, and `RaveForgetRequest` are transient commands and should use the existing memory-Params command path.
- If the offroad/onroad state becomes ambiguous or changes to onroad during pairing, cancel pairing and ignore later confirmation.
- Successful credentials must survive normal enable/disable state changes and C3X reboot.
- Forget must remove the persisted peer credentials as one coherent operation.

Never expose the raw pairing key in logs, screenshots, diagnostics, or user-visible output.

Simulator/endpoint pairing-key files are sensitive artifacts:

- Store them with restrictive permissions (`0600` where supported).
- Do not commit or upload them.
- Do not delete only one side's pairing material and leave the other side believing the pair is valid; coordinate key deletion with the explicit Forget operation.

---

## 10. RAVE must not rely entirely on user-defined danger zones

Danger-zone determination must not depend 100% on the user drawing or calibrating a region correctly.

User configuration may assist calibration, but a bad user configuration must not be the sole thing separating a safe interpretation from an unsafe one.

The production pipeline needs a consistent system-derived understanding of the danger region / adjacent-lane threat state.

Any temporal model or geometric logic added for this purpose must still obey the Pi 5 performance and latency rules above.

---

## 11. Model / perception direction

Current RAVE perception direction:

- YOLO26 Nano-class detector is the intended lightweight detector family unless profiling proves a better fit.
- Bounding boxes are preferred; segmentation is not required for the current safety objective.
- Primary classes are `vehicle` and `motorcycle`.
- Vehicle tracking is part of the pipeline.
- Temporal reasoning may use a lightweight GRU/transformer-style model only if measured Pi 5 headroom supports it.
- Better training data is preferred over compensating for poor detections with increasingly expensive runtime logic.

Do not silently expand model scope in a way that increases latency or compute cost without measurement.

### Current validated development-camera baseline

Treat these as a **development baseline**, not immutable production constants:

- Arducam B0589 USB/UVC rear camera.
- 1920x1080 MJPEG capture at 60 FPS.
- Latest-frame behavior: keep the newest useful frame and do not build a backlog.
- Current live-inference crop: 1920x391, `y=300:691`.
- YOLO input size: 960.
- Confidence `0.05` is a validated development baseline, not a permanent safety threshold.
- Model execution is intentionally bounded around 30 FPS while capture remains 60 FPS.
- The current validated runtime path is 1080p; do not silently switch production capture to 4K without revalidating latency, buffering, ISP/HDR behavior, USB load, and Pi 5 performance.

A benchmark-specific crop or experiment must not silently replace the canonical live-inference crop.

### Dataset, annotation, and checkpoint hygiene

Model quality work continues in parallel with integration, but dataset integrity comes before another training run.

- Maintain genuinely separate train/validation/test sets.
- Avoid leakage from duplicate or near-adjacent frames from the same sequence/drive across splits.
- Preserve the class schema (`vehicle`, `motorcycle`) unless an explicit dataset/model migration is planned.
- Validate `data.yaml`, label format, class IDs, file/label counts, and dataset lineage before training.
- Audit checkpoint lineage before fine-tuning; do not confuse model parameter count with cumulative training depth.
- Quarantine broken/incompatible checkpoints rather than silently selecting them.
- Prefer versioned training configuration and logged run metadata over hardcoded hyperparameters copied into scripts or documentation.
- Do not compensate for label/data problems by adding heavier runtime compute.
- Keep large raw recordings temporary when appropriate, but preserve the extracted/curated data and lineage needed to reproduce training decisions.

---

## 12. One canonical simulator, not disposable patches

The RAVE simulator is a validation product, not a throwaway script.

There should be **one canonical simulator implementation** in the active RAVE branch.

Do not create `rave_sim_v2.py`, `rave_sim_fixed.py`, `rave_sim_new.py`, temporary forks, or multiple competing launchers because a bug was found. Fix the canonical simulator unless a migration is explicitly planned.

Simulator requirements:

- Interactive GUI suitable for repeated engineering use.
- Readable typography and controls.
- Clear network status.
- Clear pairing/authenticated-session status.
- Independent LEFT/RIGHT controls.
- CLEAR/WATCH/WARNING controls.
- OK/DEGRADED/FAULT health controls.
- Stale/pause testing.
- Session/Pi restart testing.
- Cable/network loss recovery testing.
- Invalid HMAC testing.
- Malformed packet testing.
- Duplicate testing.
- Out-of-order testing.
- Replay testing.
- Useful bounded event logging.
- Immediate visual acknowledgement of operator actions.
- No 10 Hz wall of useless packet log spam.
- Network disappearance should produce a clear waiting/retrying state, not an uncontrolled exception loop.
- Network return should recover automatically when technically possible.

The simulator must exercise the real production codec, pairing, HMAC, and session rules. Do not create a fake test-only transport that bypasses production security or freshness semantics.

Simulator threat selection must be operator-controlled and **must not depend on Comma vehicle state**. A simulator regression that requires Comma blinker, blind-spot, speed, or other vehicle telemetry is a regression toward the removed architecture.

The simulator may keep a pairing credential for repeat testing, but that credential is sensitive and must follow the pairing-key handling rules above.

---

## 13. UI/UX is part of quality, not decoration

Engineering tools and vehicle UI must be easy to understand and difficult to misuse.

Required habits:

- Use readable fonts for body text and controls.
- Decorative/futuristic fonts belong only in limited branding/title use.
- Buttons must have clear labels and adequate touch/click targets.
- Status must be visible without reading terminal logs.
- Error states must explain what failed in plain language.
- Avoid ambiguous controls such as a button labeled `Pair` that only enables a network service.
- Important operations should provide visible acknowledgement.
- Logs should document meaningful state transitions and failures, not overwhelm the user.

A technically functional tool with poor feedback or misleading controls is not considered finished.

For RAVE engineering kits/updaters:

- Preserve user configuration unless the migration explicitly changes it.
- Prefer atomic configuration writes.
- Back up before replacing a working installation and provide a rollback path when practical.
- Do not mutate a known-good CUDA/PyTorch/system environment unnecessarily.
- Prevent updates from racing an active inference session.
- Keep one canonical installer/updater/launcher per workflow instead of accumulating corrected copies.

---

## 14. Deployment integrity: source and generated binaries must agree

A previous deployment restored an old generated `common/params_pyx.so` to permit checkout. The new source contained RAVE Param keys while the stale binary did not. The result was `UnknownKeyName` when the Raylib Pair UI attempted to write `RaveEnabled`, which crashed the UI process and caused manager to restart it.

This lesson must not be repeated.

Rules:

- Do not assume source changes are active merely because `git checkout` succeeded.
- If native/generated outputs depend on changed source, rebuild them.
- After changing RAVE Param registration, verify the compiled Python Params binding recognizes the keys.
- A deployment preflight must explicitly test a harmless RAVE Params read/write before declaring deployment good.
- Do not restore stale generated binaries from an old branch and then forget they were restored.
- Prefer reproducible build/deployment scripts over one-off manual repair commands.

A valid preflight includes confirming that `Params().put_bool("RaveEnabled", False)` succeeds on the deployed source/build before testing pairing UI.

---

## 15. Protect user/local work on the C3X

Do not use destructive Git cleanup casually on the device.

Before branch changes or deployments:

- Inspect `git status`.
- Identify generated artifacts separately from real user/theme/config/source edits.
- Do not use `git reset --hard` or broad `git clean` unless the exact consequences were reviewed and intentionally accepted.
- Do not bulldoze unrelated local files merely to make a checkout easy.

When a narrow restore is needed, restore only reviewed paths.

---

## 16. C3X command convention

When giving commands intended to be launched from the ZBook against the C3X, provide the Wi-Fi SSH wrapper so the command can be pasted directly.

Administrative SSH baseline:

```bash
ssh -i ~/.ssh/rave_comma_ed25519 comma@192.168.0.87 'bash -s' <<'REMOTE'
cd /data/openpilot || exit 1

# C3X commands here

REMOTE
```

Do not assume the operator is already inside a comma shell unless explicitly stated.

The dedicated RAVE Ethernet link is runtime transport; Wi-Fi SSH is acceptable for administration/debugging.

---

## 17. Dedicated wired transport baseline

RAVE runtime communication uses the dedicated Ethernet link.

Known-good baseline:

- Pi/ZBook side: `10.77.0.1/24`
- C3X side: `10.77.0.2/24`
- No gateway.
- No DNS.
- Never-default routing.
- IPv6 disabled on the dedicated RAVE profile.
- Runtime UDP port: `47771`.
- Pairing UDP port: `47772`.

Do not make runtime RAVE dependent on Wi-Fi.

### Backend-owned NetworkManager contract

The StarPilot backend owns the dedicated C3X RAVE adapter. The vehicle UI does not.

Required provisioning behavior:

- Discover **exactly one** eligible USB Ethernet adapter.
- Supported software families currently include ASIX `ax88179_178a` and Realtek `r8152`.
- Never hardcode `eth0`, a MAC address, or a generated NetworkManager profile UUID.
- Configure C3X IPv4 `10.77.0.2/24`, no gateway, no DNS, `never-default=yes`, IPv6 disabled, and autoconnect enabled.
- Preserve Wi-Fi/LTE, default routes, DNS, and unrelated Ethernet profiles.
- Missing or ambiguous eligible adapters fail unavailable; do not guess and modify an unrelated interface.
- Network-changing operations are offroad-gated.
- The backend owns/persists its generated profile identity in `RaveNetworkProfileUuid`.
- `RaveNetworkStatus` must stay within the bounded states: `disabled`, `adapterMissing`, `adapterAmbiguous`, `configuring`, `connected`, `profileConflict`, `networkError`.
- Dry-run mode must not mutate NetworkManager or Params.
- A failed postcondition must fail closed by deactivating only the selected RAVE adapter/profile, not by disturbing unrelated networking.
- `rave_networkd` remains a dynamically managed, non-control-critical process.
- Fresh supported hardware should ultimately provision without requiring an end user to SSH, run `nmcli`, use a terminal, choose a MAC/interface, or hand-edit NetworkManager.

Developer/admin SSH is a separate matter and remains acceptable for engineering diagnostics.

### Adapter qualification is specific, not generic

Do not treat all USB Ethernet adapters as equivalent just because Linux recognizes them.

- **Realtek RTL8153 using the `r8152` driver (`0bda:8153`) is tested, approved, and part of the known-good C3X RAVE wired-transport baseline.**
- The Realtek path has been hardware-validated for the dedicated `10.77.0.0/24` RAVE link and must not be downgraded to “experimental,” “hotplug-only,” or “not reboot-qualified” based on older pre-validation notes.
- ASIX AX88179/AX88179A (`ax88179_178a`, including validated `0b95:1790` hardware) is also supported/validated where recorded by the deployment tests.
- Qualification claims must follow the latest recorded hardware validation, not an older intermediate test state.
- Component-level success does not automatically qualify an untested adapter model merely because it uses a related chipset/driver.
- Never hardcode a test-generated profile UUID.

Do not assume the Ethernet adapter/cable is physically connected. Observe actual link/interface state before diagnosing a disconnected interface as a software failure.

---

## 18. Do not make assumptions that can be measured

A recurring quality problem is jumping to an assumed cause before checking observable state.

Rules:

- Do not assume Ethernet is connected.
- Do not assume a process is running because it should be.
- Do not assume a branch contains a change because it was intended to.
- Do not assume a generated binary matches source.
- Do not assume a UI button performs the operation its label implies.
- Do not assume a simulator command reached the C3X merely because the simulator accepted the click.
- Do not assume the old Qt UI path is active on a Raylib build.
- Do not assume a development-host result proves Pi 5 behavior.
- Do not overwrite a newer approved hardware result with an older intermediate qualification note; the Realtek RTL8153/r8152 C3X path is an approved baseline.
- Do not assume a sender timestamp can be compared to a receiver timestamp across devices.
- Do not assume a benchmark crop/config is the current production-development baseline.

Prefer one high-value observation that separates causes over a long checklist of speculative fixes.

---

## 19. Root-cause fixes over patch accumulation

Do not respond to every failure by layering another workaround.

Before adding a patch:

- Identify which component actually failed.
- Verify the failure path.
- Fix the owning layer.
- Remove obsolete workaround code when the canonical fix supersedes it.
- Avoid duplicate scripts and duplicate implementations.

Lessons already learned:

- Original onroad `commIssue` was isolated to `rave_linkd`, not `rave_networkd` or Gate 2C rendering.
- Removing continuous Comma -> Pi vehicle-state runtime traffic fixed the original `commIssue`.
- The newer Firestar C3X UI is Raylib, so Qt-only RAVE warning code cannot be treated as production integration.
- The visible Pair button was not actually driving the authenticated pairing workflow; labels must match behavior.
- The UI Pair crash came from stale generated Params bindings, not Ethernet hardware or the RX-only architecture.
- A disconnected Ethernet adapter is a physical state, not evidence of a simulator networking bug.
- A simulator that requires repeated one-off terminal commands is not adequate as the canonical validation tool.
- Cross-device monotonic timestamps are not a freshness clock; use receiver-local arrival time.
- Backend network provisioning must preserve normal Wi-Fi/default routing and must never guess between multiple eligible adapters.
- x86 host UI artifacts and device-target C3X artifacts must remain isolated; generated host outputs must not leak into commits or device deployment.
- Component-level validation is not full-system qualification.
- When project evidence evolves, the newest completed hardware validation supersedes an older intermediate failure/qualification note unless the newer result explicitly says otherwise.

Do not reopen already-proven root causes without new evidence.

---

## 20. Validation gates

Do not jump directly from a code change to a driving test.

Minimum progression for C3X/RAVE UI/runtime work:

1. Static/syntax/build checks.
2. Unit tests for pure warning/security/state logic.
3. Offroad C3X process/Params validation.
4. RAVE disabled baseline — normal StarPilot behavior.
5. RAVE enabled with Ethernet absent — no UI crash, no `commIssue`, fail-dark.
6. Ethernet connection/recovery.
7. Real authenticated pairing through the production flow.
8. Reboot persistence of pairing credentials.
9. Parked/onroad warning-state tests.
10. Stale/fault/auth/network-loss tests.
11. Original `commIssue` regression check.
12. Performance/CPU/UI-frame-time check.
13. Only then: short controlled drive validation.

Never advise a driving test with an active `commIssue` or other unresolved system fault.

Do not interact with laptops/terminals while the vehicle is moving.

---

## 21. Required parked warning matrix

Before calling Raylib Gate 2C warning integration validated, exercise at least:

- Left CLEAR.
- Left WATCH.
- Left WARNING.
- Right CLEAR.
- Right WATCH.
- Right WARNING.
- Simultaneous left/right WATCH.
- Simultaneous left/right WARNING.
- Mixed left WATCH / right WARNING.
- Health OK.
- Health DEGRADED.
- Health FAULT -> fail-dark.
- No message -> fail-dark.
- Local stale receipt -> fail-dark.
- `packetAgeMs > 275` -> fail-dark.
- Session restart -> fail-dark until authenticated session returns.
- Cable unplug -> fail-dark without `commIssue`.
- Cable replug -> recover without unnecessary manual restart.
- Endpoint process death -> fail-dark without `commIssue`.
- Invalid HMAC -> rejected/fail-dark.
- Replay/duplicate/out-of-order -> rejected/fail-dark as appropriate.

---

## 22. Performance validation rules

Measure performance rather than assuming a change is cheap.

For C3X UI integration:

- `raveState` is nominally ~10 Hz.
- Eligibility/render logic should be trivial relative to normal UI work.
- Do not create new polling threads or high-rate loops for RAVE UI.
- Compare UI frame timing/CPU before and after RAVE integration if the change affects the render/update loop.

For Pi5 perception:

- Measure capture age, inference age, tracker age, and output age where possible.
- Frame age matters more than queued throughput.
- A system that reports high FPS while processing old frames is unacceptable.

### Host UI and device-target build isolation

Desktop simulation and C3X deployment are different build products.

- Keep host-native/x86 Raylib/Qt/replay artifacts isolated under the host runtime (for example `.host_runtime`) rather than polluting the device-target source/build tree.
- Host runtime buckets are disposable; production source and device artifacts are not.
- Do not commit x86-64 replacements for ARM64/device-target generated artifacts.
- Use desktop Raylib/replay simulation for fast visual iteration before C3X deployment when it can reproduce the relevant behavior.
- Use the real device-target build path for C3X-compatible artifacts; a successful desktop UI run does not prove the device build.
- After switching branches/bases, revalidate both host simulation and device-target/native dependencies that changed.

---

## 23. Logging and diagnostics

Logs should make failures diagnosable without becoming a performance problem.

Required principles:

- Log state transitions and meaningful failures.
- Keep counters for malformed/authentication/replay/session-restart/stale behavior where useful.
- Avoid per-frame and per-packet spam in normal operation.
- Never log raw pairing/master keys.
- Prefer concise summaries over giant dumps.
- Simulator logs should clearly distinguish operator actions, network state, pairing state, session state, transmitted threat state, and injected faults.
- Protect credential files, model weights, generated artifacts, and private data from accidental commits/uploads.
- Mock/synthetic modes must be explicitly gated and clearly labeled so development data cannot be mistaken for production state.

---

## 24. Quality bar: no avoidable quality escapes

Before handing the user a script, installer, simulator update, deployment command, or code patch:

- Check syntax.
- Check paths against the active branch.
- Check that the targeted UI/runtime implementation is actually the one in use.
- Check for duplicate/obsolete files created by the change.
- Check that error paths do not crash the UI.
- Check that the change does not silently alter security behavior.
- Check that the change does not create new vehicle-control dependencies.
- Check that logs are useful.
- Check that UI text is readable.
- Check that commands are copy/paste-safe.
- Check assumptions about physical hardware state before diagnosing hardware/network behavior.
- Validate the actual failure mechanism before proposing a fix.
- Run the relevant unit tests and syntax/compile checks; also run shell checks, lint/type checks, or `git diff --check` where the changed files/workflow support them.
- Distinguish implemented behavior, validated behavior, planned behavior, scaffolding, and mock behavior in code/comments/docs.
- Keep placeholders inactive by default.
- Review the exact intended changed/staged file set before significant commits.

If something cannot be validated locally, state exactly what remains hardware-dependent instead of presenting it as already proven.

### Release-readiness boundary

Do not call the complete RAVE system production-ready until the remaining release gates have been satisfied, including as applicable:

- Pi 5 end-to-end inference/tracking/temporal latency and sustained frame-age validation.
- Pi 5 thermal, memory, USB/I/O, and compute-headroom validation.
- Automotive power, brownout/shutdown, storage-endurance, thermal-soak, vibration, and EMI/environment validation.
- Exact supported hardware compatibility/self-test gates.
- Reproducible Pi deployment image/services.
- Signed, atomic, reversible application and model update path with rollback.
- Simulation, replay, fault injection, closed-course validation, and controlled road validation.

Application/model updates intended for release must eventually be signed, atomic, reversible, and subject to appropriate safety-state controls.

---

## 25. Canonical baseline and rebasing discipline

The RX-only RAVE fix was hardware validated before migration to the newer Firestar base. Its purpose and behavior are architectural invariants even when commit hashes change during rebases.

Do not confuse a rebased commit hash with a change in the validated design.

When rebasing RAVE onto newer Firestar:

- Re-evaluate UI architecture changes carefully.
- Do not blindly resolve conflicts with `ours`/`theirs` without understanding rebase semantics.
- Reapply RAVE behavior on top of the current Firestar architecture rather than forcing old architecture back into the tree.
- Re-run the `commIssue` regression and fail-dark validation after migration.
- Verify generated/native artifacts match the new source after checkout/build.

Git/review discipline:

- Significant RAVE commits should use descriptive commit bodies that record the safety/architecture intent, not only a vague one-line subject.
- Verify the exact intended file set before committing.
- Do not silently commit, amend, force-update, or push unless the task explicitly authorizes that action.
- Keep historical/validated commit IDs as traceability, not as a reason to bypass current-source review after a rebase.

---

## 26. Definition of done for a RAVE feature

A RAVE feature is not done merely because code runs once.

It is done when:

- The owning architecture is correct.
- Safety invariants are preserved.
- Failure behavior is defined and tested.
- Pi5/C3X performance impact is acceptable.
- UI/UX is clear enough to use repeatedly without guesswork.
- Deployment is reproducible.
- Logs provide useful diagnostics.
- There is one canonical implementation.
- Relevant regression tests exist.
- Hardware validation has been completed when hardware behavior is part of the claim.

---

## 27. Three rules that survive every future refactor

**RAVE may consume resources on the comma, but normal comma/openpilot operation must never depend on RAVE.**

**Loss of trustworthy RAVE data must remove RAVE information immediately; it must never manufacture a vehicle-stack fault or continue displaying stale danger information.**

**RAVE is advisory perception. The Pi must never become a Panda/CAN/vehicle-control endpoint, and the C3X must never convert RAVE metadata directly into actuation.**
