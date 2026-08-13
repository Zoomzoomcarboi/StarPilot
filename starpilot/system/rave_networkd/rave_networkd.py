from __future__ import annotations

import argparse
import json
import signal
import threading
import time
import uuid
from dataclasses import asdict
from typing import Any

from openpilot.common.params import Params
from openpilot.common.swaglog import cloudlog
from openpilot.starpilot.system.rave_networkd.network_manager import Adapter, AuthorizationError, NetworkManagerClient, NetworkManagerError, Profile

PROFILE_NAME = "RAVE Ethernet"
RAVE_ADDRESS = "10.77.0.2/24"
RETRY_DELAYS = (2.0, 5.0, 10.0, 30.0)
VALID_STATES = frozenset(("disabled", "adapterMissing", "adapterAmbiguous", "configuring", "connected",
                          "profileConflict", "networkError"))
VALID_REASONS = frozenset(("none", "noAdapter", "multipleAdapters", "ownedProfileMissing", "ownershipMismatch",
                           "onroadChangeBlocked", "adapterChanged", "authorizationFailed", "networkManagerUnavailable",
                           "adapterDisappeared", "addressMismatch", "defaultRouteChanged", "primaryConnectionChanged",
                           "dnsChanged", "ipv6RouteChanged", "activationFailed"))


def profile_settings(profile_uuid: str, adapter: Adapter) -> dict[str, dict[str, tuple[str, Any]]]:
  return {
    "connection": {
      "id": ("s", PROFILE_NAME), "uuid": ("s", profile_uuid), "type": ("s", "802-3-ethernet"),
      "autoconnect": ("b", True), "autoconnect-retries": ("i", 0), "autoconnect-priority": ("i", 100),
    },
    "802-3-ethernet": {"mac-address": ("ay", bytes.fromhex(adapter.permanent_mac.replace(":", "")))},
    "ipv4": {
      "method": ("s", "manual"),
      "address-data": ("aa{sv}", [{"address": ("s", "10.77.0.2"), "prefix": ("u", 24)}]),
      "gateway": ("s", ""), "dns": ("au", []), "dns-search": ("as", []),
      "ignore-auto-dns": ("b", True), "never-default": ("b", True),
    },
    "ipv6": {"method": ("s", "disabled"), "never-default": ("b", True), "ignore-auto-dns": ("b", True)},
  }


def profile_is_exact(profile: Profile, adapter: Adapter) -> bool:
  expected = profile_settings(profile.uuid, adapter)
  for section, values in expected.items():
    actual = profile.settings.get(section, {})
    for key, value in values.items():
      actual_value = actual.get(key)
      if actual_value is None and value in (("s", ""), ("au", []), ("as", [])):
        continue
      if section == "802-3-ethernet" and key == "mac-address" and actual_value is not None:
        if bytes(actual_value[1]) != bytes(value[1]):
          return False
      elif actual_value != value:
        return False
  return True


class RaveNetworkDaemon:
  def __init__(self, backend=None, params=None, monotonic=time.monotonic, sleeper=time.sleep, backend_factory=NetworkManagerClient):
    self.backend = backend
    self.backend_factory = backend_factory
    self.params = params or Params()
    self.monotonic = monotonic
    self.sleeper = sleeper
    self._last_status = None
    self._stopped = False
    self._stop_event = threading.Event()
    self._retry_index = 0

  def stop(self, *_args):
    self._stopped = True
    self._stop_event.set()

  def _status(self, state: str, reason: str = "none", adapter: Adapter | None = None) -> dict:
    assert state in VALID_STATES and reason in VALID_REASONS
    value = {"state": state, "reason": reason}
    if adapter is not None:
      value.update({"interface": adapter.interface, "driver": adapter.driver,
                    "usbId": f"{adapter.usb_vendor}:{adapter.usb_product}" if adapter.usb_vendor else ""})
    if value != self._last_status:
      self.params.put("RaveNetworkStatus", value)
      self._last_status = value
    return value

  def _owned_profile(self, profiles: list[Profile]) -> tuple[Profile | None, str | None]:
    owned_uuid = self.params.get("RaveNetworkProfileUuid") or ""
    if not owned_uuid:
      return None, None
    profile = next((p for p in profiles if p.uuid == owned_uuid), None)
    return profile, owned_uuid

  def reconcile(self, offroad: bool, dry_run: bool = False) -> dict:
    def status(state: str, reason: str = "none", adapter: Adapter | None = None) -> dict:
      if dry_run:
        value = {"state": state, "reason": reason}
        if adapter is not None:
          value["adapter"] = asdict(adapter)
        return value
      return self._status(state, reason, adapter)

    try:
      if self.backend is None:
        self.backend = self.backend_factory()
      adapters = self.backend.list_adapters()
      if not adapters:
        result = status("adapterMissing", "noAdapter")
        if dry_run:
          result["snapshot"] = asdict(self.backend.snapshot())
        return result
      if len(adapters) > 1:
        result = status("adapterAmbiguous", "multipleAdapters")
        if dry_run:
          result["adapters"] = [asdict(adapter) for adapter in adapters]
          result["snapshot"] = asdict(self.backend.snapshot())
        return result
      adapter = adapters[0]
      profiles = self.backend.list_profiles()
      owned, owned_uuid = self._owned_profile(profiles)

      if owned_uuid and owned is None:
        if not offroad:
          return status("profileConflict", "ownedProfileMissing", adapter)
        owned_uuid = None

      adapter_changed = False
      if owned is not None:
        mac = owned.settings.get("802-3-ethernet", {}).get("mac-address", ("ay", b""))[1]
        expected_mac = bytes.fromhex(adapter.permanent_mac.replace(":", ""))
        if bytes(mac) != expected_mac:
          if not offroad:
            return status("profileConflict", "adapterChanged", adapter)
          adapter_changed = True

      needs_create = owned is None
      needs_update = owned is not None and (adapter_changed or not profile_is_exact(owned, adapter))
      active = self.backend.active_profile_on_device(adapter)
      needs_takeover = active is not None and (owned is None or active.uuid != owned.uuid)
      if not offroad and (needs_create or needs_update or needs_takeover):
        return status("profileConflict", "onroadChangeBlocked", adapter)

      before = self.backend.snapshot()
      current_addresses = self.backend.device_ipv4_addresses(adapter)
      plan = {"state": "configuring", "reason": "none", "adapter": asdict(adapter),
              "ownedProfile": owned.uuid if owned else "", "activeProfile": active.uuid if active else "",
              "create": needs_create, "update": needs_update, "deactivateSelectedAdapter": needs_takeover,
              "activate": active is None or owned is None or active.uuid != owned.uuid,
              "currentAddresses": current_addresses,
              "target": {"ipv4": RAVE_ADDRESS, "gateway": "none", "dns": "none", "neverDefault": True,
                         "ipv6": "disabled", "autoconnect": True},
              "snapshot": asdict(before)}
      if dry_run:
        return plan
      status("configuring", adapter=adapter)

      if needs_create:
        new_uuid = str(uuid.uuid4())
        owned = self.backend.add_profile(profile_settings(new_uuid, adapter))
        self.params.put("RaveNetworkProfileUuid", new_uuid)
      elif needs_update:
        owned = self.backend.update_profile(owned, profile_settings(owned.uuid, adapter))
      assert owned is not None

      if needs_takeover:
        self.backend.deactivate_device_connection(adapter)
      active = self.backend.active_profile_on_device(adapter)
      if active is None or active.uuid != owned.uuid:
        self.backend.activate_profile(owned, adapter)

      deadline = self.monotonic() + 5.0
      addresses = self.backend.device_ipv4_addresses(adapter)
      while RAVE_ADDRESS not in addresses and self.monotonic() < deadline and not self._stopped:
        self.sleeper(0.25)
        addresses = self.backend.device_ipv4_addresses(adapter)
      after = self.backend.snapshot()
      if RAVE_ADDRESS not in addresses:
        self.backend.deactivate_device_connection(adapter)
        return status("networkError", "addressMismatch", adapter)
      if before.primary_connection != after.primary_connection:
        self.backend.deactivate_device_connection(adapter)
        return status("networkError", "primaryConnectionChanged", adapter)
      if before.dns != after.dns:
        self.backend.deactivate_device_connection(adapter)
        return status("networkError", "dnsChanged", adapter)
      if before.ipv4_default_routes != after.ipv4_default_routes:
        self.backend.deactivate_device_connection(adapter)
        return status("networkError", "defaultRouteChanged", adapter)
      if before.ipv6_default_routes != after.ipv6_default_routes:
        self.backend.deactivate_device_connection(adapter)
        return status("networkError", "ipv6RouteChanged", adapter)
      if any(interface == adapter.interface for interface, _ in after.ipv4_default_routes + after.ipv6_default_routes):
        self.backend.deactivate_device_connection(adapter)
        return status("networkError", "defaultRouteChanged", adapter)
      return status("connected", adapter=adapter)
    except AuthorizationError:
      return status("networkError", "authorizationFailed")
    except NetworkManagerError:
      self.backend = None
      return status("networkError", "networkManagerUnavailable")
    except (OSError, ValueError, KeyError):
      return status("networkError", "adapterDisappeared")
    except Exception:
      cloudlog.exception("unexpected RAVE NetworkManager failure")
      self.backend = None
      return status("networkError", "networkManagerUnavailable")

  def run(self):
    while not self._stopped and self.params.get_bool("RaveEnabled"):
      offroad = self.params.get_bool("IsOffroad") and not self.params.get_bool("IsOnroad")
      result = self.reconcile(offroad)
      if result["state"] == "connected":
        self._retry_index = 0
        delay = 10.0
      else:
        delay = RETRY_DELAYS[min(self._retry_index, len(RETRY_DELAYS) - 1)]
        self._retry_index = min(self._retry_index + 1, len(RETRY_DELAYS) - 1)
      if self.sleeper is time.sleep:
        self._stop_event.wait(delay)
      else:
        self.sleeper(delay)
    self._status("disabled")


def main() -> None:
  parser = argparse.ArgumentParser(description="Provision the dedicated RAVE Ethernet link")
  parser.add_argument("--dry-run", action="store_true", help="inspect and print the plan without modifying NetworkManager")
  args = parser.parse_args()
  daemon = RaveNetworkDaemon()
  if args.dry_run:
    offroad = daemon.params.get_bool("IsOffroad") and not daemon.params.get_bool("IsOnroad")
    print(json.dumps(daemon.reconcile(offroad, dry_run=True), indent=2, sort_keys=True))
    return
  signal.signal(signal.SIGTERM, daemon.stop)
  signal.signal(signal.SIGINT, daemon.stop)
  daemon.run()


if __name__ == "__main__":
  main()
