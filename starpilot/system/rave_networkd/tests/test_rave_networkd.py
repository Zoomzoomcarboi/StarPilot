from copy import deepcopy
import sys
from types import SimpleNamespace
import pytest

from openpilot.starpilot.system.rave_networkd.network_manager import (
  Adapter, AuthorizationError, NetworkManagerClient, NetworkManagerError, NetworkSnapshot, Profile, _driver_from_sysfs,
)
from openpilot.starpilot.system.rave_networkd.rave_networkd import (
  RAVE_ADDRESS, RETRY_DELAYS, RaveNetworkDaemon, profile_is_exact, profile_settings,
)

# Keep this isolated unit suite independent of the full controls import graph.
sys.modules.setdefault("openpilot.system.sentry", SimpleNamespace(capture_exception=lambda *_args, **_kwargs: None))
from openpilot.system.manager.process import ensure_running
from openpilot.system.manager.process_config import managed_processes


class FakeParams:
  def __init__(self, values=None):
    self.values = dict(values or {})
    self.writes = []

  def get(self, key):
    return self.values.get(key)

  def get_bool(self, key):
    return bool(self.values.get(key, False))

  def put(self, key, value):
    self.values[key] = value
    self.writes.append((key, value))

  def remove(self, key):
    self.values.pop(key, None)


class FakeBackend:
  def __init__(self, adapters=None, profiles=None, active=None):
    self.adapters = list(adapters or [])
    self.profiles = list(profiles or [])
    self.active = active
    self.addresses = (RAVE_ADDRESS,)
    self.before = NetworkSnapshot("/wifi", (("wlan0", "192.168.1.1"),), (), ("1.1.1.1",))
    self.after = self.before
    self.calls = []
    self.error = None

  def _raise(self):
    if self.error:
      raise self.error

  def list_adapters(self):
    self._raise()
    return self.adapters

  def list_profiles(self): return self.profiles
  def active_profile_on_device(self, adapter): return self.active
  def snapshot(self):
    self.calls.append("snapshot")
    return self.before if self.calls.count("snapshot") == 1 else self.after
  def device_ipv4_addresses(self, adapter): return self.addresses

  def add_profile(self, settings):
    profile = Profile("/owned", settings["connection"]["uuid"][1], settings["connection"]["id"][1], settings)
    self.profiles.append(profile)
    self.calls.append("add")
    return profile

  def update_profile(self, profile, settings):
    updated = Profile(profile.path, profile.uuid, profile.name, settings)
    self.profiles[self.profiles.index(profile)] = updated
    self.calls.append("update")
    return updated

  def deactivate_device_connection(self, adapter):
    self.calls.append("deactivate")
    self.active = None

  def activate_profile(self, profile, adapter):
    self.calls.append("activate")
    self.active = profile


AX = Adapter("/ax", "enx123", "ax88179_178a", "00:11:22:33:44:55", "0b95", "1790")
RTL = Adapter("/rtl", "usbnet9", "r8152", "aa:bb:cc:dd:ee:ff", "0bda", "8153")


def owned(adapter=AX, uuid="owned", name="RAVE Ethernet"):
  return Profile("/owned", uuid, name, profile_settings(uuid, adapter))


def daemon(backend, values=None):
  params = FakeParams({"IsOffroad": True, "RaveEnabled": True} | (values or {}))
  return RaveNetworkDaemon(backend, params=params, sleeper=lambda _: None), params


@pytest.mark.parametrize("driver", ["ax88179_178a", "r8152"])
def test_supported_usb_driver_resolution(tmp_path, driver):
  sys_net = tmp_path / "net"
  usb = tmp_path / "usb" / "1-1"
  device = usb / "1-1:1.0"
  drivers = tmp_path / "drivers"
  device.mkdir(parents=True)
  (drivers / driver).mkdir(parents=True)
  (usb / "idVendor").write_text("0b95\n")
  (usb / "idProduct").write_text("1790\n")
  (sys_net / "renamed0").mkdir(parents=True)
  (sys_net / "renamed0" / "device").symlink_to(device, target_is_directory=True)
  (device / "driver").symlink_to(drivers / driver, target_is_directory=True)
  assert _driver_from_sysfs("renamed0", sys_net) == (driver, "0b95", "1790")


def test_unsupported_or_non_ethernet_candidates_are_absent():
  d, _ = daemon(FakeBackend([]))
  assert d.reconcile(True)["state"] == "adapterMissing"


@pytest.mark.parametrize("device_type", [2, 8, 999])
def test_wifi_modem_and_unsupported_devices_are_ignored(tmp_path, device_type):
  client = object.__new__(NetworkManagerClient)
  client._sys_class_net = tmp_path
  client._nm = object()
  client._call = lambda *_args: (["/device"],)
  client._properties = lambda *_args: {"DeviceType": ("u", device_type), "Interface": ("s", "wlan0")}
  assert client.list_adapters() == []


def test_one_candidate_and_interface_name_irrelevant():
  d, _ = daemon(FakeBackend([RTL]))
  result = d.reconcile(True)
  assert result["state"] == "connected"
  assert result["interface"] == "usbnet9"


def test_two_candidates_are_ambiguous_without_mutation():
  backend = FakeBackend([AX, RTL])
  d, _ = daemon(backend)
  assert d.reconcile(True)["state"] == "adapterAmbiguous"
  assert backend.calls == []


def test_profile_settings_are_exact_and_mac_is_device_specific():
  settings = profile_settings("u", RTL)
  assert settings["ipv4"]["method"] == ("s", "manual")
  assert settings["ipv4"]["address-data"] == ("aa{sv}", [{"address": ("s", "10.77.0.2"), "prefix": ("u", 24)}])
  assert settings["ipv4"]["gateway"] == ("s", "")
  assert settings["ipv4"]["never-default"] == ("b", True)
  assert settings["ipv4"]["ignore-auto-dns"] == ("b", True)
  assert settings["ipv4"]["dns"] == ("au", [])
  assert settings["ipv6"]["method"] == ("s", "disabled")
  assert settings["connection"]["autoconnect"] == ("b", True)
  assert settings["802-3-ethernet"]["mac-address"][1] == bytes.fromhex("aabbccddeeff")


def test_owned_profile_created_and_uuid_persisted():
  backend = FakeBackend([AX])
  d, params = daemon(backend)
  assert d.reconcile(True)["state"] == "connected"
  assert "add" in backend.calls
  assert params.get("RaveNetworkProfileUuid") == backend.active.uuid


def test_unrelated_same_name_profile_is_not_touched():
  unrelated = owned(uuid="someone-elses")
  backend = FakeBackend([AX], [unrelated])
  d, params = daemon(backend)
  d.reconcile(True)
  assert unrelated in backend.profiles
  assert params.get("RaveNetworkProfileUuid") != unrelated.uuid
  assert "update" not in backend.calls


def test_stale_owned_uuid_replaced_only_offroad():
  backend = FakeBackend([AX])
  d, params = daemon(backend, {"RaveNetworkProfileUuid": "stale"})
  assert d.reconcile(False)["reason"] == "ownedProfileMissing"
  assert params.get("RaveNetworkProfileUuid") == "stale"
  assert d.reconcile(True)["state"] == "connected"
  assert params.get("RaveNetworkProfileUuid") != "stale"


def test_generic_profile_takeover_offroad_without_delete():
  generic = Profile("/dhcp", "dhcp", "Wired connection 1", {})
  backend = FakeBackend([AX], [generic], active=generic)
  d, _ = daemon(backend)
  assert d.reconcile(True)["state"] == "connected"
  assert "deactivate" in backend.calls and "activate" in backend.calls
  assert generic in backend.profiles


def test_no_creation_or_takeover_onroad():
  generic = Profile("/dhcp", "dhcp", "Wired", {})
  backend = FakeBackend([AX], [generic], active=generic)
  d, _ = daemon(backend)
  assert d.reconcile(False)["reason"] == "onroadChangeBlocked"
  assert "add" not in backend.calls and "deactivate" not in backend.calls


def test_existing_owned_profile_reactivates_onroad():
  profile = owned()
  backend = FakeBackend([AX], [profile])
  d, _ = daemon(backend, {"RaveNetworkProfileUuid": profile.uuid})
  assert d.reconcile(False)["state"] == "connected"
  assert backend.calls.count("activate") == 1


def test_replacement_adapter_rebinds_owned_profile_only_offroad():
  profile = owned(AX)
  backend = FakeBackend([RTL], [profile])
  d, _ = daemon(backend, {"RaveNetworkProfileUuid": profile.uuid})
  assert d.reconcile(False)["reason"] == "adapterChanged"
  assert "update" not in backend.calls
  assert d.reconcile(True)["state"] == "connected"
  assert "update" in backend.calls
  assert backend.active.settings["802-3-ethernet"]["mac-address"][1] == bytes.fromhex("aabbccddeeff")


@pytest.mark.parametrize("field,changed,reason", [
  ("primary_connection", "/lte", "primaryConnectionChanged"),
  ("ipv4_default_routes", (("eth9", ""),), "defaultRouteChanged"),
  ("ipv6_default_routes", (("eth9", ""),), "ipv6RouteChanged"),
  ("dns", ("9.9.9.9",), "dnsChanged"),
])
def test_routing_dns_postconditions(field, changed, reason):
  profile = owned()
  backend = FakeBackend([AX], [profile], active=profile)
  backend.after = NetworkSnapshot(**({**backend.before.__dict__, field: changed}))
  d, _ = daemon(backend, {"RaveNetworkProfileUuid": profile.uuid})
  assert d.reconcile(False)["reason"] == reason
  assert "deactivate" in backend.calls


def test_address_mismatch_and_adapter_disappearance():
  profile = owned()
  backend = FakeBackend([AX], [profile], active=profile)
  backend.addresses = ()
  now = [0.0]
  params = FakeParams({"RaveEnabled": True, "RaveNetworkProfileUuid": profile.uuid})
  d = RaveNetworkDaemon(backend, params, monotonic=lambda: now[0], sleeper=lambda delay: now.__setitem__(0, now[0] + delay))
  assert d.reconcile(False)["reason"] == "addressMismatch"
  backend.device_ipv4_addresses = lambda _: (_ for _ in ()).throw(OSError())
  assert d.reconcile(False)["reason"] == "adapterDisappeared"


@pytest.mark.parametrize("error,reason", [(NetworkManagerError(), "networkManagerUnavailable"),
                                           (AuthorizationError(), "authorizationFailed")])
def test_network_manager_failures_are_sanitized(error, reason):
  backend = FakeBackend([AX])
  backend.error = error
  d, _ = daemon(backend)
  assert d.reconcile(True) == {"state": "networkError", "reason": reason}


def test_status_writes_only_on_semantic_change_and_dry_run_is_read_only():
  backend = FakeBackend([])
  d, params = daemon(backend)
  d.reconcile(True)
  d.reconcile(True)
  assert len(params.writes) == 1
  before = deepcopy(params.values)
  d.reconcile(True, dry_run=True)
  assert params.values == before


def test_retry_backoff_is_bounded_and_not_busy_looping():
  sleeps = []
  backend = FakeBackend([])
  params = FakeParams({"RaveEnabled": True})
  d = RaveNetworkDaemon(backend, params, sleeper=lambda delay: (sleeps.append(delay), params.values.update(RaveEnabled=len(sleeps) < 6)))
  d.run()
  assert sleeps == [2.0, 5.0, 10.0, 30.0, 30.0, 30.0]
  assert min(sleeps) >= min(RETRY_DELAYS)


def test_profile_extra_networkmanager_fields_are_allowed():
  profile = owned()
  profile.settings["connection"]["timestamp"] = ("t", 1)
  assert profile_is_exact(profile, AX)


def test_manager_registration_is_noncritical_and_predicate_is_dynamic(monkeypatch):
  proc = managed_processes["rave_networkd"]
  params = FakeParams({"RaveEnabled": False})
  assert not proc.control_critical
  assert not proc.should_run(False, params, SimpleNamespace(), SimpleNamespace())
  params.values["RaveEnabled"] = True
  assert proc.should_run(False, params, SimpleNamespace(), SimpleNamespace())
  assert proc.should_run(True, params, SimpleNamespace(), SimpleNamespace())

  calls = []
  monkeypatch.setattr(proc, "enabled", True)
  monkeypatch.setattr(proc, "start", lambda: calls.append("start"))
  monkeypatch.setattr(proc, "stop", lambda **_kwargs: calls.append("stop"))
  monkeypatch.setattr(proc, "check_watchdog", lambda _started: None)
  params.values["RaveEnabled"] = False
  ensure_running([proc], False, params, SimpleNamespace(), starpilot_toggles=SimpleNamespace())
  params.values["RaveEnabled"] = True
  ensure_running([proc], False, params, SimpleNamespace(), starpilot_toggles=SimpleNamespace())
  params.values["RaveEnabled"] = False
  ensure_running([proc], True, params, SimpleNamespace(), starpilot_toggles=SimpleNamespace())
  assert calls == ["stop", "start", "stop"]


def test_noncritical_manager_state_cannot_trigger_process_not_running():
  proc = managed_processes["rave_networkd"]
  proc.proc = SimpleNamespace(is_alive=lambda: False, pid=123, exitcode=1)
  state = proc.get_process_state_msg()
  assert not state.shouldBeRunning
  assert not {p.name for p in [state] if not p.running and p.shouldBeRunning}
  proc.proc = None
