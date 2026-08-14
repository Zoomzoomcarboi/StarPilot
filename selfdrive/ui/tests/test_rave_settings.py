"""Focused RAVE UI tests use unittest to match the adjacent Aether test harness."""
# ruff: noqa: TID251

import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch


RAVE_MODULE = "openpilot.selfdrive.ui.layouts.settings.starpilot.rave"
RAVE_PATH = Path(__file__).parents[1] / "layouts/settings/starpilot/rave.py"


class FakeParams:
  def __init__(self, values=None):
    self.values = dict(values or {})
    self.writes = []

  def get(self, key, **_kwargs):
    return self.values.get(key)

  def get_bool(self, key, **_kwargs):
    return bool(self.values.get(key, False))

  def put_bool_nonblocking(self, key, value):
    self.values[key] = value
    self.writes.append((key, value))


class FakeUIState:
  def __init__(self):
    self.offroad = True
    self.sm = types.SimpleNamespace(valid={"managerState": False})

  def is_offroad(self):
    return self.offroad


def load_rave_module():
  colors = types.SimpleNamespace(
    SUCCESS="success", WARNING="warning", DANGER="danger", PRIMARY="primary", MUTED="muted")

  class SettingRow:
    def __init__(self, row_id, row_type, title, **kwargs):
      self.id, self.type, self.title = row_id, row_type, title
      self.__dict__.update(kwargs)

  class SettingSection:
    def __init__(self, title, rows):
      self.title, self.rows = title, rows

  class AetherSettingsView:
    def __init__(self, controller, sections, **kwargs):
      self._controller, self._sections = controller, sections
      self.__dict__.update({f"_{key}": value for key, value in kwargs.items()})

    def _render(self, _rect):
      pass

    def _draw_row(self, _rect, _row, _is_last):
      pass

    def show_event(self):
      self._pressed_target = None

    def hide_event(self):
      self._pressed_target = None

  class SettingsPage:
    def __init__(self):
      self._params = FakeParams()
      self._current_sub_panel = ""
      self._navigate_callback = None

    def _navigate_to(self, sub_panel):
      if sub_panel != self._current_sub_panel:
        self._current_sub_panel = sub_panel
        if self._navigate_callback:
          self._navigate_callback(sub_panel)

    def _wire_sub_panels(self):
      pass

    def _go_back(self):
      self._current_sub_panel = ""

  aether = types.ModuleType("openpilot.selfdrive.ui.layouts.settings.starpilot.aethergrid")
  aether.AetherListColors = colors
  aether.AetherSettingsView = AetherSettingsView
  aether.SettingRow = SettingRow
  aether.SettingSection = SettingSection
  aether.draw_settings_list_row = lambda *_args, **_kwargs: None
  panel = types.ModuleType("openpilot.selfdrive.ui.layouts.settings.starpilot.panel")
  panel._SettingsPage = SettingsPage
  ui_state_module = types.ModuleType("openpilot.selfdrive.ui.ui_state")
  ui_state_module.ui_state = FakeUIState()
  multilang = types.ModuleType("openpilot.system.ui.lib.multilang")
  multilang.tr = lambda text: text

  stubs = {
    aether.__name__: aether,
    panel.__name__: panel,
    ui_state_module.__name__: ui_state_module,
    multilang.__name__: multilang,
  }
  with patch.dict(sys.modules, stubs):
    spec = importlib.util.spec_from_file_location(RAVE_MODULE, RAVE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[RAVE_MODULE] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
  return module, ui_state_module.ui_state


class TestRaveStatusParsing(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    cls.rave, cls.ui_state = load_rave_module()

  def test_every_known_state(self):
    for state in (
      "disabled", "adapterMissing", "adapterAmbiguous", "configuring", "connected",
      "profileConflict", "networkError",
    ):
      with self.subTest(state=state):
        self.assertEqual(self.rave.parse_rave_network_status({"state": state}).state.value, state)

  def test_invalid_inputs_are_unavailable(self):
    for raw in (None, "", "{bad", "[]", [], 42, {"state": "unknown"}, {"state": 12}):
      with self.subTest(raw=raw):
        status = self.rave.parse_rave_network_status(raw)
        self.assertEqual(status.state, self.rave.RaveNetworkState.UNAVAILABLE)

  def test_wrong_field_types_are_safe_and_diagnostics_are_bounded(self):
    status = self.rave.parse_rave_network_status({
      "state": "networkError", "reason": "x" * 1000, "interface": ["eth0"],
      "driver": 12, "usbId": None,
    })
    self.assertLessEqual(len(status.reason), self.rave.MAX_DIAGNOSTIC_LENGTH)
    self.assertTrue(status.reason.endswith("…"))
    self.assertEqual((status.interface, status.driver, status.usb_id), ("", "", ""))

  def test_bytes_and_json_objects_are_supported(self):
    status = self.rave.parse_rave_network_status(b'{"state":"connected","interface":"eth0"}')
    self.assertEqual(status.state, self.rave.RaveNetworkState.CONNECTED)
    self.assertEqual(status.interface, "eth0")


class TestRaveStateController(unittest.TestCase):
  def setUp(self):
    self.rave, self.ui_state = load_rave_module()
    self.ui_state.offroad = True

  def controller(self, enabled, state, running):
    params = FakeParams({"RaveEnabled": enabled, "RaveNetworkStatus": {"state": state}})
    return self.rave.RaveStateController(params, networkd_running=lambda: running), params

  def test_connected_requires_enabled_and_running_networkd(self):
    controller, _ = self.controller(True, "connected", True)
    self.assertTrue(controller.refresh().connected)
    self.assertEqual(controller.snapshot.title, "Connected")

    controller, _ = self.controller(False, "connected", True)
    self.assertFalse(controller.refresh().connected)
    self.assertEqual(controller.snapshot.title, "Connection Status Unavailable")

    controller, _ = self.controller(True, "connected", False)
    self.assertFalse(controller.refresh().connected)
    self.assertEqual(controller.snapshot.title, "Connection Status Unavailable")

  def test_networkd_running_uses_subscribed_manager_state(self):
    class FakeSubMaster:
      valid = {"managerState": True}

      def __getitem__(self, service):
        self.assert_service = service
        return types.SimpleNamespace(processes=[
          types.SimpleNamespace(name="ui", running=True),
          types.SimpleNamespace(name="rave_networkd", running=True),
        ])

    self.ui_state.sm = FakeSubMaster()
    self.assertTrue(self.rave.rave_networkd_running())
    self.assertEqual(self.ui_state.sm.assert_service, "managerState")

  def test_malformed_status_never_displays_connected(self):
    params = FakeParams({"RaveEnabled": True, "RaveNetworkStatus": "{bad"})
    controller = self.rave.RaveStateController(params, networkd_running=lambda: True)
    self.assertFalse(controller.refresh().connected)
    self.assertNotEqual(controller.snapshot.title, "Connected")

  def test_status_is_reparsed_only_when_raw_value_changes(self):
    controller, params = self.controller(True, "adapterMissing", True)
    with patch.object(self.rave, "parse_rave_network_status", wraps=self.rave.parse_rave_network_status) as parser:
      controller.refresh()
      controller.refresh()
      self.assertEqual(parser.call_count, 1)
      params.values["RaveNetworkStatus"] = {"state": "configuring"}
      controller.refresh()
      self.assertEqual(parser.call_count, 2)

  def test_setup_action_is_offroad_gated_and_rechecked(self):
    controller, params = self.controller(False, "disabled", False)
    controller.refresh()
    self.assertTrue(controller.start_setup())
    self.assertEqual(params.writes, [("RaveEnabled", True)])

    params.values["RaveEnabled"] = False
    params.writes.clear()
    self.ui_state.offroad = False
    self.assertFalse(controller.start_setup())
    self.assertEqual(params.writes, [])

  def test_configuring_and_redundant_actions_do_not_write(self):
    controller, params = self.controller(False, "configuring", True)
    controller.refresh()
    self.assertFalse(controller.start_setup())
    self.assertEqual(params.writes, [])

    params.values["RaveEnabled"] = True
    self.assertFalse(controller.set_enabled(True))
    self.assertEqual(params.writes, [])

  def test_toggle_is_conservatively_offroad_gated(self):
    controller, params = self.controller(True, "adapterMissing", True)
    self.ui_state.offroad = False
    self.assertFalse(controller.set_enabled(False))
    self.assertEqual(params.writes, [])

  def test_setup_view_disables_pair_onroad_and_while_active(self):
    controller, params = self.controller(False, "disabled", False)
    owner = types.SimpleNamespace(_rave_state=controller, _go_back=lambda: None)
    view = self.rave._RaveSetupView(owner)
    controller.refresh()
    self.assertTrue(view._pair_enabled())
    self.ui_state.offroad = False
    self.assertFalse(view._pair_enabled())
    self.ui_state.offroad = True
    params.values["RaveEnabled"] = True
    controller.refresh()
    self.assertFalse(view._pair_enabled())

  def test_show_hide_ephemeral_state_does_not_replace_backend_state(self):
    controller, _ = self.controller(True, "adapterMissing", True)
    before = controller.refresh()
    owner = types.SimpleNamespace(_rave_state=controller, _go_back=lambda: None)
    view = self.rave._RaveSetupView(owner)
    view._pressed_target = "action:pair"
    view.hide_event()
    self.assertIsNone(view._pressed_target)
    view._pressed_target = "action:pair"
    view.show_event()
    self.assertIsNone(view._pressed_target)
    self.assertEqual(controller.snapshot, before)


class TestRaveNavigationRegistration(unittest.TestCase):
  def test_native_navigation_registration_is_complete(self):
    panel_source = (RAVE_PATH.parent / "panel.py").read_text()
    main_source = (RAVE_PATH.parent / "main_panel.py").read_text()
    self.assertIn("RAVE = 13", panel_source)
    self.assertIn('"panel": "RAVE"', main_source)
    self.assertIn('"icon": "rave"', main_source)
    self.assertIn("uniform_width=True", main_source)
    self.assertIn("StarPilotPanelType.RAVE: StarPilotPanelInfo", main_source)
    self.assertIn('"RAVE": StarPilotPanelType.RAVE', main_source)
    self.assertIn("StarPilotPanelType.RAVE,", main_source)

  def test_layout_uses_normal_setup_child_navigation(self):
    rave, _ = load_rave_module()
    layout = rave.StarPilotRaveLayout()
    self.assertIn("SETUP", layout._sub_panels)
    self.assertIn("DETAILS", layout._sub_panels)
    self.assertEqual(layout._current_sub_panel, "")
    stack = []
    layout._navigate_callback = lambda name: stack.append(name) if name else stack.pop()
    layout._navigate_to("SETUP")
    self.assertEqual(stack, ["SETUP"])
    self.assertEqual(layout._current_sub_panel, "SETUP")
    done_row = next(row for section in layout._sub_panels["SETUP"]._sections
                    for row in section.rows if row.id == "done")
    done_row.on_click()
    self.assertEqual(layout._current_sub_panel, "")
    self.assertEqual(stack, [])


if __name__ == "__main__":
  unittest.main()
