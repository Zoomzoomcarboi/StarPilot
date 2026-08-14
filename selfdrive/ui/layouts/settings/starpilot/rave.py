from __future__ import annotations

import json
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any

from openpilot.selfdrive.ui.layouts.settings.starpilot.aethergrid import (
  AetherListColors,
  AetherSettingsView,
  SettingRow,
  SettingSection,
  draw_settings_list_row,
)
from openpilot.selfdrive.ui.layouts.settings.starpilot.panel import _SettingsPage
from openpilot.selfdrive.ui.ui_state import ui_state
from openpilot.system.ui.lib.multilang import tr


RAVE_ENABLED_PARAM = "RaveEnabled"
RAVE_STATUS_PARAM = "RaveNetworkStatus"
RAVE_NETWORK_PROCESS = "rave_networkd"
MAX_DIAGNOSTIC_LENGTH = 96


class RaveNetworkState(str, Enum):
  DISABLED = "disabled"
  ADAPTER_MISSING = "adapterMissing"
  ADAPTER_AMBIGUOUS = "adapterAmbiguous"
  CONFIGURING = "configuring"
  CONNECTED = "connected"
  PROFILE_CONFLICT = "profileConflict"
  NETWORK_ERROR = "networkError"
  UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class RaveNetworkStatus:
  state: RaveNetworkState
  reason: str = ""
  interface: str = ""
  driver: str = ""
  usb_id: str = ""


@dataclass(frozen=True)
class RavePresentation:
  status: RaveNetworkStatus
  enabled: bool
  networkd_running: bool
  title: str
  guidance: str
  color: Any

  @property
  def connected(self) -> bool:
    return self.enabled and self.networkd_running and self.status.state == RaveNetworkState.CONNECTED


def _bounded_string(value: object) -> str:
  if not isinstance(value, str):
    return ""
  clean = " ".join(value.split())
  if len(clean) <= MAX_DIAGNOSTIC_LENGTH:
    return clean
  return clean[:MAX_DIAGNOSTIC_LENGTH - 1].rstrip() + "…"


def parse_rave_network_status(raw: object) -> RaveNetworkStatus:
  data: object = raw
  if isinstance(raw, bytes):
    try:
      data = raw.decode("utf-8")
    except UnicodeDecodeError:
      return RaveNetworkStatus(RaveNetworkState.UNAVAILABLE)
  if isinstance(data, str):
    try:
      data = json.loads(data)
    except (json.JSONDecodeError, TypeError, ValueError):
      return RaveNetworkStatus(RaveNetworkState.UNAVAILABLE)
  if not isinstance(data, dict):
    return RaveNetworkStatus(RaveNetworkState.UNAVAILABLE)

  raw_state = data.get("state")
  try:
    state = RaveNetworkState(raw_state) if isinstance(raw_state, str) else RaveNetworkState.UNAVAILABLE
  except ValueError:
    state = RaveNetworkState.UNAVAILABLE

  return RaveNetworkStatus(
    state=state,
    reason=_bounded_string(data.get("reason")),
    interface=_bounded_string(data.get("interface")),
    driver=_bounded_string(data.get("driver")),
    usb_id=_bounded_string(data.get("usbId")),
  )


def rave_networkd_running() -> bool:
  try:
    if not ui_state.sm.valid.get("managerState", False):
      return False
    return any(process.name == RAVE_NETWORK_PROCESS and process.running
               for process in ui_state.sm["managerState"].processes)
  except (AttributeError, KeyError, TypeError):
    return False


class RaveStateController:
  def __init__(self, params, networkd_running=rave_networkd_running):
    self._params = params
    self._networkd_running = networkd_running
    self._last_raw: object = object()
    self._parsed_status = RaveNetworkStatus(RaveNetworkState.UNAVAILABLE)
    self._snapshot = self._presentation(False, False, self._parsed_status)

  @property
  def snapshot(self) -> RavePresentation:
    return self._snapshot

  def refresh(self) -> RavePresentation:
    raw = self._params.get(RAVE_STATUS_PARAM)
    if raw != self._last_raw:
      self._parsed_status = parse_rave_network_status(raw)
      self._last_raw = raw
    enabled = self._params.get_bool(RAVE_ENABLED_PARAM)
    running = bool(self._networkd_running())
    self._snapshot = self._presentation(enabled, running, self._parsed_status)
    return self._snapshot

  @staticmethod
  def _presentation(enabled: bool, running: bool, status: RaveNetworkStatus) -> RavePresentation:
    state = status.state
    if state == RaveNetworkState.CONNECTED:
      if enabled and running:
        return RavePresentation(status, enabled, running, "Connected",
                                "Your wired RAVE connection is ready.", AetherListColors.SUCCESS)
      return RavePresentation(status, enabled, running, "Connection Status Unavailable",
                              "RAVE cannot confirm that the saved connection is active.", AetherListColors.WARNING)
    if state == RaveNetworkState.CONFIGURING and enabled:
      return RavePresentation(status, enabled, running, "Configuring",
                              "Adapter detected. Configuring RAVE…", AetherListColors.PRIMARY)
    if state == RaveNetworkState.ADAPTER_AMBIGUOUS:
      return RavePresentation(status, enabled, running, "Attention Required",
                              "Leave only the supported RAVE Ethernet adapter connected.", AetherListColors.WARNING)
    if state == RaveNetworkState.PROFILE_CONFLICT:
      return RavePresentation(status, enabled, running, "Attention Required",
                              "RAVE could not safely prepare its Ethernet connection.", AetherListColors.WARNING)
    if state == RaveNetworkState.NETWORK_ERROR:
      return RavePresentation(status, enabled, running, "Attention Required",
                              "RAVE encountered a network setup problem.", AetherListColors.DANGER)
    if state == RaveNetworkState.ADAPTER_MISSING and enabled:
      return RavePresentation(status, enabled, running, "Setup Required",
                              "Connect a supported RAVE Ethernet adapter.", AetherListColors.WARNING)
    if state == RaveNetworkState.DISABLED or not enabled:
      return RavePresentation(status, enabled, running, "Setup Required",
                              "Enable RAVE to begin Ethernet setup.", AetherListColors.MUTED)
    return RavePresentation(status, enabled, running, "Connection Status Unavailable",
                            "RAVE has not reported a usable connection state.", AetherListColors.WARNING)

  def set_enabled(self, enabled: bool) -> bool:
    if not ui_state.is_offroad():
      return False
    if self._params.get_bool(RAVE_ENABLED_PARAM) == enabled:
      return False
    self._params.put_bool_nonblocking(RAVE_ENABLED_PARAM, enabled)
    return True

  def start_setup(self) -> bool:
    if not ui_state.is_offroad():
      return False
    if self.snapshot.status.state == RaveNetworkState.CONFIGURING:
      return False
    if self._params.get_bool(RAVE_ENABLED_PARAM):
      return False
    self._params.put_bool_nonblocking(RAVE_ENABLED_PARAM, True)
    return True


class _RaveSettingsView(AetherSettingsView):
  def __init__(self, controller: StarPilotRaveLayout):
    self._rave = controller._rave_state
    sections = [
      SettingSection("RAVE Status", [
        SettingRow("status", "value", "RAVE", subtitle="Rear Awareness Vision Engine",
                   get_value=lambda: tr(self._rave.snapshot.title)),
      ]),
      SettingSection("Settings", [
        SettingRow("enabled", "toggle", "Enable RAVE",
                   subtitle="Use the wired Rear Awareness Vision Engine.",
                   disabled_label="Available while parked",
                   enabled=ui_state.is_offroad,
                   get_state=lambda: self._rave.snapshot.enabled,
                   set_state=self._rave.set_enabled),
        SettingRow("connection", "value", "RAVE Ethernet",
                   subtitle="Connection and guided setup",
                   get_value=lambda: tr(self._rave.snapshot.title), on_click=lambda: None, navigate_to="SETUP"),
        SettingRow("details", "value", "Connection Details",
                   subtitle="Technical adapter and backend information",
                   get_value=lambda: tr("View"), on_click=lambda: None, navigate_to="DETAILS"),
      ]),
    ]
    super().__init__(controller, sections, header_title="RAVE",
                     header_subtitle="Rear Awareness Vision Engine")

  def _render(self, rect):
    self._rave.refresh()
    super()._render(rect)

  def _draw_row(self, rect, row, is_last):
    if row.id != "status":
      super()._draw_row(rect, row, is_last)
      return
    target_id = f"{row.type}:{row.id}"
    hovered, pressed = self._interactive_state(target_id, rect)
    draw_settings_list_row(
      rect,
      title=tr(row.title),
      subtitle=tr(self._rave.snapshot.guidance),
      value=tr(self._rave.snapshot.title),
      hovered=hovered,
      pressed=pressed,
      is_last=is_last,
      show_chevron=False,
      value_color=self._rave.snapshot.color,
      title_size=41,
      subtitle_size=28,
      value_size=34,
      style=self._panel_style,
    )


class _RaveSetupView(AetherSettingsView):
  def __init__(self, controller: StarPilotRaveLayout):
    self._rave = controller._rave_state
    sections = [
      SettingSection("Setup Status", [
        SettingRow("setup_status", "value", "RAVE Ethernet",
                   get_value=lambda: tr(self._rave.snapshot.title)),
      ]),
      SettingSection("Setup", [
        SettingRow("pair", "action", "Pair RAVE",
                   subtitle="Connect the adapter, then RAVE will configure it automatically.",
                   disabled_label="Available while parked or when setup is not already active",
                   visible=lambda: not self._rave.snapshot.connected,
                   enabled=self._pair_enabled, on_click=self._rave.start_setup,
                   action_text="PAIR"),
        SettingRow("done", "action", "Done", subtitle="Return to RAVE Settings.",
                   visible=lambda: self._rave.snapshot.connected,
                   on_click=lambda: controller._navigate_to(""), action_text="DONE"),
      ]),
    ]
    super().__init__(controller, sections, header_title="RAVE Setup",
                     header_subtitle="Connect a supported RAVE Ethernet adapter to the comma's secondary USB port.")

  def _pair_enabled(self) -> bool:
    return (ui_state.is_offroad() and not self._rave.snapshot.enabled and
            self._rave.snapshot.status.state != RaveNetworkState.CONFIGURING)

  def _draw_row(self, rect, row, is_last):
    if row.id == "setup_status":
      row = replace(row, subtitle=self._rave.snapshot.guidance)
    super()._draw_row(rect, row, is_last)

  def _render(self, rect):
    self._rave.refresh()
    super()._render(rect)


class _RaveDetailsView(AetherSettingsView):
  def __init__(self, controller: StarPilotRaveLayout):
    self._rave = controller._rave_state
    sections = [
      SettingSection("Adapter", [
        SettingRow("interface", "value", "Interface", get_value=lambda: self._value("interface")),
        SettingRow("driver", "value", "Driver", get_value=lambda: self._value("driver")),
        SettingRow("usb_id", "value", "USB ID", get_value=lambda: self._value("usb_id")),
      ]),
      SettingSection("Backend", [
        SettingRow("reason", "value", "Reason", get_value=lambda: self._value("reason")),
      ]),
    ]
    super().__init__(controller, sections, header_title="Connection Details",
                     header_subtitle="Technical information reported by the RAVE backend.")

  def _value(self, field: str) -> str:
    return getattr(self._rave.snapshot.status, field) or tr("Not reported")

  def _render(self, rect):
    self._rave.refresh()
    super()._render(rect)


class StarPilotRaveLayout(_SettingsPage):
  def __init__(self):
    super().__init__()
    self._rave_state = RaveStateController(self._params)
    self._manager_view = _RaveSettingsView(self)
    self._sub_panels = {
      "SETUP": _RaveSetupView(self),
      "DETAILS": _RaveDetailsView(self),
    }
    self._wire_sub_panels()
