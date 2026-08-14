from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jeepney import DBusAddress, new_method_call
from jeepney.io.blocking import open_dbus_connection
from jeepney.low_level import MessageType
from jeepney.wrappers import Properties

from openpilot.system.ui.lib.networkmanager import (
  NM, NM_ACTIVE_CONNECTION_IFACE, NM_CONNECTION_IFACE, NM_DEVICE_IFACE,
  NM_DEVICE_TYPE_ETHERNET, NM_IFACE, NM_IP4_CONFIG_IFACE, NM_PATH,
  NM_SETTINGS_IFACE, NM_SETTINGS_PATH, NM_WIRED_IFACE,
)

SUPPORTED_DRIVERS = frozenset(("ax88179_178a", "r8152"))


class NetworkManagerError(RuntimeError):
  pass


class AuthorizationError(NetworkManagerError):
  pass


class ProfileRejectedError(NetworkManagerError):
  pass


@dataclass(frozen=True)
class Adapter:
  path: str
  interface: str
  driver: str
  permanent_mac: str
  usb_vendor: str = ""
  usb_product: str = ""


@dataclass(frozen=True)
class Profile:
  path: str
  uuid: str
  name: str
  settings: dict[str, dict[str, tuple[str, Any]]]


@dataclass(frozen=True)
class NetworkSnapshot:
  primary_connection: str
  ipv4_default_routes: tuple[tuple[str, str], ...]
  ipv6_default_routes: tuple[tuple[str, str], ...]
  dns: tuple[str, ...]


def _variant_value(value: Any, default: Any = None) -> Any:
  return value[1] if isinstance(value, tuple) and len(value) == 2 else default


def _device_details_from_sysfs(interface: str, sys_class_net: Path) -> tuple[str, bool, str, str]:
  device = sys_class_net / interface / "device"
  driver_path = device / "driver"
  if not driver_path.exists():
    return "", False, "", ""
  try:
    driver = os.path.basename(os.path.realpath(driver_path))
  except OSError:
    return "", False, "", ""
  usb_ancestry = False
  vendor = product = ""
  try:
    current = device.resolve()
    for parent in (current, *current.parents):
      vendor_path, product_path = parent / "idVendor", parent / "idProduct"
      subsystem = parent / "subsystem"
      if os.path.basename(os.path.realpath(subsystem)) == "usb" or vendor_path.is_file() or product_path.is_file():
        usb_ancestry = True
        if vendor_path.is_file():
          vendor = vendor_path.read_text().strip().lower()
        if product_path.is_file():
          product = product_path.read_text().strip().lower()
        break
  except OSError:
    pass
  return driver, usb_ancestry, vendor, product


def _driver_from_sysfs(interface: str, sys_class_net: Path = Path("/sys/class/net")) -> tuple[str, str, str]:
  driver, _, vendor, product = _device_details_from_sysfs(interface, sys_class_net)
  return driver, vendor, product


class NetworkManagerClient:
  """Small synchronous NetworkManager D-Bus client used outside the UI thread."""

  def __init__(self, sys_class_net: Path = Path("/sys/class/net")):
    self._conn = open_dbus_connection(bus="SYSTEM")
    self._nm = DBusAddress(NM_PATH, bus_name=NM, interface=NM_IFACE)
    self._sys_class_net = sys_class_net

  def _call(self, address: DBusAddress, method: str, signature: str | None = None, body: tuple = ()):
    msg = new_method_call(address, method, signature, body) if signature else new_method_call(address, method)
    try:
      reply = self._conn.send_and_get_reply(msg, timeout=5.0)
    except (OSError, TimeoutError) as e:
      raise NetworkManagerError("networkManagerUnavailable") from e
    if reply.header.message_type == MessageType.error:
      error_name = str(reply.header.fields)
      if "AccessDenied" in error_name or "NotAuthorized" in error_name:
        raise AuthorizationError("authorizationFailed")
      if "org.freedesktop.NetworkManager.Settings.Connection." in error_name:
        raise ProfileRejectedError("profileRejected")
      raise NetworkManagerError("dbusError")
    return reply.body

  def _properties(self, path: str, interface: str) -> dict:
    address = DBusAddress(path, bus_name=NM, interface=interface)
    try:
      reply = self._conn.send_and_get_reply(Properties(address).get_all(), timeout=5.0)
    except (OSError, TimeoutError) as e:
      raise NetworkManagerError("networkManagerUnavailable") from e
    if reply.header.message_type == MessageType.error:
      raise NetworkManagerError("dbusError")
    return dict(reply.body[0])

  def list_adapters(self) -> list[Adapter]:
    adapters = []
    for path in self._call(self._nm, "GetDevices")[0]:
      props = self._properties(str(path), NM_DEVICE_IFACE)
      if int(_variant_value(props.get("DeviceType"), 0)) != NM_DEVICE_TYPE_ETHERNET:
        continue
      interface = str(_variant_value(props.get("Interface"), ""))
      driver, usb_ancestry, vendor, product = _device_details_from_sysfs(interface, self._sys_class_net)
      if driver not in SUPPORTED_DRIVERS or not usb_ancestry:
        continue
      wired_props = self._properties(str(path), NM_WIRED_IFACE)
      permanent_mac = str(_variant_value(wired_props.get("PermHwAddress"), "")).lower()
      adapters.append(Adapter(str(path), interface, driver, permanent_mac, vendor, product))
    return adapters

  def list_profiles(self) -> list[Profile]:
    settings_addr = DBusAddress(NM_SETTINGS_PATH, bus_name=NM, interface=NM_SETTINGS_IFACE)
    profiles = []
    for path in self._call(settings_addr, "ListConnections")[0]:
      address = DBusAddress(str(path), bus_name=NM, interface=NM_CONNECTION_IFACE)
      settings = dict(self._call(address, "GetSettings")[0])
      connection = settings.get("connection", {})
      profiles.append(Profile(str(path), str(_variant_value(connection.get("uuid"), "")),
                              str(_variant_value(connection.get("id"), "")), settings))
    return profiles

  def add_profile(self, settings: dict) -> Profile:
    address = DBusAddress(NM_SETTINGS_PATH, bus_name=NM, interface=NM_SETTINGS_IFACE)
    path = str(self._call(address, "AddConnection", "a{sa{sv}}", (settings,))[0])
    uuid = str(_variant_value(settings["connection"]["uuid"], ""))
    return Profile(path, uuid, str(_variant_value(settings["connection"]["id"], "")), settings)

  def update_profile(self, profile: Profile, settings: dict) -> Profile:
    address = DBusAddress(profile.path, bus_name=NM, interface=NM_CONNECTION_IFACE)
    self._call(address, "Update", "a{sa{sv}}", (settings,))
    return Profile(profile.path, profile.uuid, profile.name, settings)

  def active_profile_on_device(self, adapter: Adapter) -> Profile | None:
    props = self._properties(adapter.path, NM_DEVICE_IFACE)
    active_path = str(_variant_value(props.get("ActiveConnection"), "/"))
    if active_path == "/":
      return None
    active = self._properties(active_path, NM_ACTIVE_CONNECTION_IFACE)
    profile_path = str(_variant_value(active.get("Connection"), "/"))
    return next((p for p in self.list_profiles() if p.path == profile_path), None)

  def deactivate_device_connection(self, adapter: Adapter) -> None:
    props = self._properties(adapter.path, NM_DEVICE_IFACE)
    active = str(_variant_value(props.get("ActiveConnection"), "/"))
    if active != "/":
      self._call(self._nm, "DeactivateConnection", "o", (active,))

  def activate_profile(self, profile: Profile, adapter: Adapter) -> None:
    self._call(self._nm, "ActivateConnection", "ooo", (profile.path, adapter.path, "/"))

  def device_ipv4_addresses(self, adapter: Adapter) -> tuple[str, ...]:
    props = self._properties(adapter.path, NM_DEVICE_IFACE)
    config_path = str(_variant_value(props.get("Ip4Config"), "/"))
    if config_path == "/":
      return ()
    config = self._properties(config_path, NM_IP4_CONFIG_IFACE)
    return tuple(f"{_variant_value(e.get('address'), '')}/{_variant_value(e.get('prefix'), 0)}"
                 for e in _variant_value(config.get("AddressData"), []) if _variant_value(e.get("address"), ""))

  def snapshot(self) -> NetworkSnapshot:
    nm_props = self._properties(NM_PATH, NM_IFACE)
    primary = str(_variant_value(nm_props.get("PrimaryConnection"), "/"))
    v4_defaults, v6_defaults, dns = [], [], []
    for active_path in _variant_value(nm_props.get("ActiveConnections"), []):
      active = self._properties(str(active_path), NM_ACTIVE_CONNECTION_IFACE)
      interface = ""
      devices = _variant_value(active.get("Devices"), [])
      if devices:
        interface = str(_variant_value(self._properties(str(devices[0]), NM_DEVICE_IFACE).get("Interface"), ""))
      for key, family, output in (("Ip4Config", 4, v4_defaults), ("Ip6Config", 6, v6_defaults)):
        config_path = str(_variant_value(active.get(key), "/"))
        if config_path == "/":
          continue
        config = self._properties(config_path, f"{NM}.IP{family}Config")
        for route in _variant_value(config.get("RouteData"), []):
          if _variant_value(route.get("dest"), "") in ("0.0.0.0", "::") and int(_variant_value(route.get("prefix"), -1)) == 0:
            output.append((interface, str(_variant_value(route.get("next-hop"), ""))))
        for entry in _variant_value(config.get("NameserverData"), []):
          address = str(_variant_value(entry.get("address"), ""))
          if address:
            dns.append(address)
    return NetworkSnapshot(primary, tuple(sorted(v4_defaults)), tuple(sorted(v6_defaults)), tuple(sorted(dns)))
