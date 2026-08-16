# RAVE Review Directive

`AGENTS.md` is the authoritative engineering contract for RAVE.

Review every RAVE change against that contract in addition to performing normal code review.

Pay particular attention to architectural changes, runtime dependencies, data-flow direction, process coupling, latency/freshness behavior, failure behavior, build integration, and regression coverage.

Do not review only whether newly added runtime behavior is implemented correctly. Review whether that behavior should exist in that process at all.

If a change appears to conflict with `AGENTS.md`, explicitly flag the conflict and identify the relevant requirement.

Do not assume a change is architecturally acceptable merely because it compiles, passes tests, is lightweight, or is technically functional.
