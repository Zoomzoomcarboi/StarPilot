from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import time

RAVE_UI_MAX_RECEIPT_AGE_S = 0.275
RAVE_MAX_PACKET_AGE_MS = 275


class RaveVisualSeverity(IntEnum):
  NONE = 0
  WATCH = 1
  WARNING = 2


@dataclass(frozen=True)
class RaveWarningState:
  left: RaveVisualSeverity = RaveVisualSeverity.NONE
  right: RaveVisualSeverity = RaveVisualSeverity.NONE


@dataclass(frozen=True)
class RaveWarningInput:
  received: bool
  valid: bool
  receipt_age_s: float
  packet_age_ms: int
  enabled: bool
  paired: bool
  connection_state: str
  health: str
  left_threat: str
  right_threat: str


def _enum_name(value) -> str:
  """Normalize pycapnp enum readers and plain strings."""
  return str(value).split(".")[-1].strip().lower()


def _severity(threat: str) -> RaveVisualSeverity:
  if threat == "warning":
    return RaveVisualSeverity.WARNING
  if threat == "watch":
    return RaveVisualSeverity.WATCH
  return RaveVisualSeverity.NONE


def evaluate_rave_warning(data: RaveWarningInput) -> RaveWarningState:
  """Gate 2C eligibility. Any uncertain input fails dark."""
  health_eligible = data.health in ("ok", "degraded")
  if (
    not data.received or
    not data.valid or
    data.receipt_age_s < 0.0 or
    data.receipt_age_s > RAVE_UI_MAX_RECEIPT_AGE_S or
    data.packet_age_ms > RAVE_MAX_PACKET_AGE_MS or
    not data.enabled or
    not data.paired or
    data.connection_state != "connected" or
    not health_eligible
  ):
    return RaveWarningState()

  return RaveWarningState(_severity(data.left_threat), _severity(data.right_threat))


def warning_state_from_submaster(sm, now: float | None = None) -> RaveWarningState:
  if "raveState" not in getattr(sm, "services", ()):
    return RaveWarningState()

  received = int(getattr(sm, "recv_frame", {}).get("raveState", 0)) > 0
  receipt_time = float(getattr(sm, "recv_time", {}).get("raveState", 0.0))
  now = time.monotonic() if now is None else now
  receipt_age_s = now - receipt_time if received else float("inf")

  try:
    state = sm["raveState"]
    data = RaveWarningInput(
      received=received,
      valid=bool(sm.valid.get("raveState", False)),
      receipt_age_s=receipt_age_s,
      packet_age_ms=int(state.packetAgeMs),
      enabled=bool(state.enabled),
      paired=bool(state.paired),
      connection_state=_enum_name(state.connectionState),
      health=_enum_name(state.health),
      left_threat=_enum_name(state.leftThreat),
      right_threat=_enum_name(state.rightThreat),
    )
  except (AttributeError, KeyError, TypeError, ValueError):
    return RaveWarningState()
  return evaluate_rave_warning(data)


def render_rave_warnings(rect, border_width: float, sm, now: float | None = None) -> RaveWarningState:
  """Draw native Raylib side warnings using the original Gate 2C visual contract."""
  state = warning_state_from_submaster(sm, now)
  if state.left == RaveVisualSeverity.NONE and state.right == RaveVisualSeverity.NONE:
    return state

  import pyray as rl

  watch_width = max(1, int(round(border_width / 2.0)))
  warning_width = max(1, int(round(border_width)))
  caution_amber = rl.Color(255, 179, 0, 210)
  urgent_red = rl.Color(255, 59, 48, 235)

  def draw_side(severity: RaveVisualSeverity, left: bool) -> None:
    if severity == RaveVisualSeverity.NONE:
      return
    width = warning_width if severity == RaveVisualSeverity.WARNING else watch_width
    color = urgent_red if severity == RaveVisualSeverity.WARNING else caution_amber
    x = int(round(rect.x if left else rect.x + rect.width - width))
    rl.draw_rectangle(x, int(round(rect.y)), width, int(round(rect.height)), color)

  draw_side(state.left, True)
  draw_side(state.right, False)
  return state
