from dataclasses import replace

from openpilot.selfdrive.ui.onroad.starpilot.rave_warning import (
  RAVE_MAX_PACKET_AGE_MS,
  RAVE_UI_MAX_RECEIPT_AGE_S,
  RaveVisualSeverity,
  RaveWarningInput,
  RaveWarningState,
  evaluate_rave_warning,
)


BASE = RaveWarningInput(
  received=True,
  valid=True,
  receipt_age_s=0.0,
  packet_age_ms=0,
  enabled=True,
  paired=True,
  connection_state="connected",
  health="ok",
  left_threat="none",
  right_threat="none",
)


def require_none(data: RaveWarningInput) -> None:
  assert evaluate_rave_warning(data) == RaveWarningState()


def test_rave_warning_freshness_contract():
  watch = replace(BASE, left_threat="watch")

  require_none(replace(watch, received=False))
  require_none(replace(watch, valid=False))

  assert evaluate_rave_warning(
    replace(watch, packet_age_ms=RAVE_MAX_PACKET_AGE_MS)
  ).left == RaveVisualSeverity.WATCH

  require_none(
    replace(watch, packet_age_ms=RAVE_MAX_PACKET_AGE_MS + 1)
  )

  assert evaluate_rave_warning(
    replace(watch, receipt_age_s=RAVE_UI_MAX_RECEIPT_AGE_S)
  ).left == RaveVisualSeverity.WATCH

  require_none(
    replace(
      watch,
      receipt_age_s=RAVE_UI_MAX_RECEIPT_AGE_S + 0.000001,
    )
  )

  # A frozen low sender-side packet age must never defeat stale
  # receiver-local arrival time.
  require_none(
    replace(
      watch,
      packet_age_ms=1,
      receipt_age_s=RAVE_UI_MAX_RECEIPT_AGE_S + 0.000001,
    )
  )

  # Future local receive time is an invalid clock relationship.
  require_none(replace(watch, receipt_age_s=-0.000001))

  # No stale warning latch: a subsequent fresh state immediately recovers.
  stale = replace(
    watch,
    receipt_age_s=RAVE_UI_MAX_RECEIPT_AGE_S + 0.1,
  )
  require_none(stale)
  assert evaluate_rave_warning(watch).left == RaveVisualSeverity.WATCH


def test_rave_warning_operating_state_contract():
  warning = replace(BASE, left_threat="warning")

  require_none(replace(warning, health="unknown"))
  require_none(replace(warning, health="fault"))
  require_none(replace(warning, enabled=False))
  require_none(replace(warning, paired=False))

  for connection_state in (
    "disabled",
    "notPaired",
    "pairing",
    "waiting",
    "stale",
    "error",
  ):
    require_none(
      replace(warning, connection_state=connection_state)
    )

  assert evaluate_rave_warning(
    replace(warning, health="degraded")
  ).left == RaveVisualSeverity.WARNING


def test_rave_warning_side_and_severity_contract():
  require_none(BASE)

  assert evaluate_rave_warning(
    replace(BASE, left_threat="watch")
  ) == RaveWarningState(
    RaveVisualSeverity.WATCH,
    RaveVisualSeverity.NONE,
  )

  assert evaluate_rave_warning(
    replace(BASE, right_threat="warning")
  ) == RaveWarningState(
    RaveVisualSeverity.NONE,
    RaveVisualSeverity.WARNING,
  )

  assert evaluate_rave_warning(
    replace(
      BASE,
      left_threat="warning",
      right_threat="warning",
    )
  ) == RaveWarningState(
    RaveVisualSeverity.WARNING,
    RaveVisualSeverity.WARNING,
  )

  assert evaluate_rave_warning(
    replace(
      BASE,
      left_threat="watch",
      right_threat="warning",
    )
  ) == RaveWarningState(
    RaveVisualSeverity.WATCH,
    RaveVisualSeverity.WARNING,
  )

  # A future/unknown enum must not invent a warning.
  require_none(
    replace(
      BASE,
      left_threat="futureValue",
      right_threat="futureValue",
    )
  )


def test_rave_warning_does_not_require_comma_vehicle_state():
  # Lane occupancy, factory BSM, blinkers, speed, carState, etc. are
  # intentionally not evaluator inputs. The authenticated Pi threat
  # classification is the advisory UI input.
  watch = replace(BASE, left_threat="watch")

  assert (
    evaluate_rave_warning(watch).left
    == RaveVisualSeverity.WATCH
  )
