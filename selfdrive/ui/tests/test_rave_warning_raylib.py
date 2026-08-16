from dataclasses import replace
import importlib
import sys
from types import ModuleType
from types import SimpleNamespace

import pytest

from openpilot.selfdrive.ui.onroad.starpilot.rave_warning import (
  RAVE_MAX_PACKET_AGE_MS,
  RAVE_UI_MAX_RECEIPT_AGE_S,
  RaveVisualSeverity,
  RaveWarningInput,
  RaveWarningState,
  evaluate_rave_warning,
  render_rave_warnings,
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


def load_starpilot_border(monkeypatch):
  def stub_module(name, **attributes):
    module = ModuleType(name)
    for key, value in attributes.items():
      setattr(module, key, value)
    monkeypatch.setitem(sys.modules, name, module)

  color = SimpleNamespace(r=1, g=2, b=3, a=255)
  stub_module(
    "openpilot.selfdrive.ui.ui_state",
    ui_state=SimpleNamespace(sm=None),
  )
  stub_module(
    "openpilot.starpilot.common.vision_bsm",
    get_fresh_vasm_state=lambda *_args: (False, False),
  )
  stub_module(
    "openpilot.selfdrive.ui.lib.starpilot_status",
    CEM_OVERRIDE_COLOR=color,
    ENGAGED_COLOR=color,
    EXPERIMENTAL_COLOR=color,
    TRAFFIC_COLOR=color,
  )
  module_name = "openpilot.selfdrive.ui.onroad.starpilot.starpilot_border"
  monkeypatch.delitem(sys.modules, module_name, raising=False)
  return importlib.import_module(module_name)


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


@pytest.mark.parametrize(("state", "expected"), [
  (RaveWarningState(), []),
  (RaveWarningState(left=RaveVisualSeverity.WATCH), [(True, 20), (True, 18)]),
  (RaveWarningState(right=RaveVisualSeverity.WATCH), [(False, 20), (False, 18)]),
  (RaveWarningState(left=RaveVisualSeverity.WARNING), [(True, 20), (True, 18)]),
  (RaveWarningState(right=RaveVisualSeverity.WARNING), [(False, 20), (False, 18)]),
])
def test_rave_curved_warning_side_severity_and_separator(monkeypatch, state, expected):
  import openpilot.selfdrive.ui.onroad.starpilot.rave_warning as rave_warning
  starpilot_border = load_starpilot_border(monkeypatch)

  calls = []
  monkeypatch.setattr(rave_warning, "warning_state_from_submaster", lambda *_args, **_kwargs: state)
  monkeypatch.setattr(
    starpilot_border,
    "draw_curved_side_warning",
    lambda _rect, _color, left, clip_width=None: calls.append((left, clip_width)),
  )

  returned = render_rave_warnings(SimpleNamespace(), 20, SimpleNamespace())
  assert returned == state
  assert calls == expected


def test_native_visible_priority_is_per_side(monkeypatch):
  import openpilot.selfdrive.ui.onroad.starpilot.rave_warning as rave_warning
  starpilot_border = load_starpilot_border(monkeypatch)

  state = RaveWarningState(RaveVisualSeverity.WARNING, RaveVisualSeverity.WATCH)
  calls = []
  monkeypatch.setattr(rave_warning, "warning_state_from_submaster", lambda *_args, **_kwargs: state)
  monkeypatch.setattr(
    starpilot_border,
    "draw_curved_side_warning",
    lambda _rect, _color, left, clip_width=None: calls.append((left, clip_width)),
  )

  render_rave_warnings(
    SimpleNamespace(), 20, SimpleNamespace(),
    native_visibility=SimpleNamespace(left=True, right=False),
  )
  assert calls == [(False, 20), (False, 18)]


def test_rave_watch_is_yellow_and_warning_is_red(monkeypatch):
  import openpilot.selfdrive.ui.onroad.starpilot.rave_warning as rave_warning
  starpilot_border = load_starpilot_border(monkeypatch)

  colors = []
  monkeypatch.setattr(
    starpilot_border,
    "draw_curved_side_warning",
    lambda _rect, color, _left, clip_width=None: colors.append((color.r, color.g, color.b, clip_width)),
  )
  monkeypatch.setattr(
    rave_warning,
    "warning_state_from_submaster",
    lambda *_args, **_kwargs: RaveWarningState(RaveVisualSeverity.WATCH, RaveVisualSeverity.WARNING),
  )

  render_rave_warnings(SimpleNamespace(), 20, SimpleNamespace())
  assert colors == [
    (0, 0, 0, 20), (255, 230, 0, 18),
    (0, 0, 0, 20), (255, 59, 48, 18),
  ]


def test_rave_separator_scales_with_native_warning_width(monkeypatch):
  import openpilot.selfdrive.ui.onroad.starpilot.rave_warning as rave_warning
  starpilot_border = load_starpilot_border(monkeypatch)

  widths = []
  monkeypatch.setattr(
    starpilot_border,
    "draw_curved_side_warning",
    lambda _rect, _color, _left, clip_width=None: widths.append(clip_width),
  )
  monkeypatch.setattr(
    rave_warning,
    "warning_state_from_submaster",
    lambda *_args, **_kwargs: RaveWarningState(left=RaveVisualSeverity.WATCH),
  )

  render_rave_warnings(SimpleNamespace(), 40, SimpleNamespace())
  assert widths == [40, 36]


def test_native_signal_flicker_visibility_matches_final_paint(monkeypatch):
  native_side_warning_color = load_starpilot_border(monkeypatch).native_side_warning_color

  flicker_on = native_side_warning_color(False, True, True, False, True)
  flicker_off = native_side_warning_color(False, True, True, False, False)
  bsm_flicker_off = native_side_warning_color(True, True, True, True, False)

  assert flicker_on.a > 0
  assert flicker_off.a == 0
  assert bsm_flicker_off.a > 0


def test_curved_primitive_clips_and_mirrors(monkeypatch):
  starpilot_border = load_starpilot_border(monkeypatch)

  scissors = []
  rounded = []
  monkeypatch.setattr(starpilot_border.rl, "begin_scissor_mode", lambda *args: scissors.append(args))
  monkeypatch.setattr(starpilot_border.rl, "draw_rectangle_rounded", lambda *args: rounded.append(args))
  monkeypatch.setattr(starpilot_border.rl, "end_scissor_mode", lambda: None)
  rect = starpilot_border.rl.Rectangle(10, 20, 100, 60)

  starpilot_border.draw_curved_side_warning(rect, starpilot_border.rl.WHITE, True, 12)
  starpilot_border.draw_curved_side_warning(rect, starpilot_border.rl.WHITE, False, 12)

  assert scissors == [(10, 20, 12, 60), (98, 20, 12, 60)]
  assert all(call[0] is rect and call[1:3] == (0.12, 10) for call in rounded)
