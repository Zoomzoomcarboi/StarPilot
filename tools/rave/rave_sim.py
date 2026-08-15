#!/usr/bin/env python3
"""RAVE Raylib simulator and protocol control console.

Network mode exercises the real RAVE pairing/runtime protocol against a comma over
10.77.0.0/24. Local UI mode publishes synthetic ``raveState`` messages directly
into a desktop StarPilot Raylib UI for fast visual validation.
"""
from __future__ import annotations

import argparse
from collections import deque
from dataclasses import dataclass
import json
import os
from pathlib import Path
import secrets
import select
import socket
import subprocess
import sys
import tempfile
import time

from openpilot.starpilot.system.rave_linkd.constants import (
  COMMA_ADDRESS,
  LaneState,
  MAX_DATAGRAM_SIZE,
  MessageType,
  PAIRING_PORT,
  RAVE_ADDRESS,
  RUNTIME_PORT,
  RaveHealth,
  ThreatLevel,
  ZERO_SESSION,
)
from openpilot.starpilot.system.rave_linkd.pairing import (
  CommaPairing,
  PairOffer,
  key_confirm_payload,
  pack_offer,
  unpack_key_install,
  unpack_probe,
  validate_complete,
)
from openpilot.starpilot.system.rave_linkd.protocol import (
  AuthenticationError,
  CHALLENGE_STRUCT,
  Packet,
  ProtocolError,
  RavePayload,
  decode_packet,
  derive_directional_keys,
  encode_packet,
  pack_rave_state,
  unpack_rave_state,
)
from openpilot.starpilot.system.rave_linkd.session import CommaSession

try:
  import pyray as rl
except ImportError:
  rl = None

STATE_PERIOD_NS = 100_000_000  # 10 Hz, matching production raveState service.
NETWORK_RETRY_NS = 1_000_000_000
EVENT_LIMIT = 160
RATE_WINDOW_NS = 2_000_000_000
GUI_WIDTH = 1360
GUI_HEIGHT = 840


@dataclass(frozen=True)
class UiEvent:
  when: float
  level: str
  message: str


class EventJournal:
  def __init__(self, log_dir: Path):
    log_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    self.text_path = log_dir / f"rave-sim_{stamp}.log"
    self.jsonl_path = log_dir / f"rave-sim_{stamp}.jsonl"
    self.events: deque[UiEvent] = deque(maxlen=EVENT_LIMIT)

  def add(self, message: str, level: str = "INFO", **fields) -> None:
    event = UiEvent(time.time(), level, message)
    self.events.append(event)
    wall = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(event.when))
    with self.text_path.open("a", encoding="utf-8") as f:
      f.write(f"{wall} [{level}] {message}\n")
    payload = {"time": event.when, "level": level, "message": message, **fields}
    with self.jsonl_path.open("a", encoding="utf-8") as f:
      f.write(json.dumps(payload, sort_keys=True) + "\n")


class PiEndpoint:
  def __init__(self, device_id: str, device_name: str, master_key: bytes | None = None,
               pi_session: bytes | None = None):
    self.device_id = device_id
    self.device_name = device_name
    self.master_key = master_key
    self.pending_key: bytes | None = None
    self.offer: PairOffer | None = None
    self.pi_session = pi_session or secrets.token_bytes(16)
    self.comma_session: bytes | None = None
    self.comma_to_rave: bytes | None = None
    self.rave_to_comma: bytes | None = None
    self.tx_sequence = 0
    self.last_valid_packet: bytes | None = None
    self.left_lane = LaneState.OCCUPIED
    self.left_threat = ThreatLevel.WATCH
    self.right_lane = LaneState.CLEAR
    self.right_threat = ThreatLevel.NONE
    self.health = RaveHealth.OK
    if master_key is not None:
      self._activate_key(master_key)

  def _activate_key(self, key: bytes) -> None:
    self.master_key = key
    self.comma_to_rave, self.rave_to_comma = derive_directional_keys(key)

  def handle_pairing(self, data: bytes, now_ns: int) -> tuple[bytes | None, str | None]:
    try:
      packet = decode_packet(data, None, allow_unauthenticated=True)
    except AuthenticationError:
      if self.pending_key is None:
        raise
      packet = decode_packet(data, self.pending_key)

    if packet.message_type == MessageType.PAIR_PROBE:
      transaction = unpack_probe(packet.payload)
      if self.offer is None or self.offer.transaction_id != transaction:
        self.offer = PairOffer(transaction, secrets.token_bytes(16), self.device_id, self.device_name)
      response = Packet(MessageType.PAIR_OFFER, ZERO_SESSION, ZERO_SESSION, 0, now_ns, pack_offer(self.offer))
      return encode_packet(response, None), "pair probe received; offer sent"

    if packet.message_type == MessageType.PAIR_KEY_INSTALL and self.offer is not None:
      transaction, nonce, device_id, key = unpack_key_install(packet.payload)
      if (transaction, nonce, device_id) != (self.offer.transaction_id, self.offer.pairing_nonce, self.device_id):
        raise ProtocolError("pairing install does not match active offer")
      self.pending_key = key
      payload = key_confirm_payload(self.offer, key)
      response = Packet(MessageType.PAIR_KEY_CONFIRM, ZERO_SESSION, ZERO_SESSION, 0, now_ns, payload)
      return encode_packet(response, key), "pair key installed; confirmation sent"

    if packet.message_type == MessageType.PAIR_COMPLETE and self.offer is not None and self.pending_key is not None:
      validate_complete(packet.payload, self.offer, self.pending_key)
      self._activate_key(self.pending_key)
      self.pending_key = None
      self.offer = None
      return None, "pairing complete; master key active"

    return None, None

  def handle_runtime(self, data: bytes, now_ns: int) -> tuple[bytes | None, str | None]:
    if self.master_key is None and self.pending_key is not None:
      pending_c2r, _ = derive_directional_keys(self.pending_key)
      try:
        packet = decode_packet(data, pending_c2r)
      except (AuthenticationError, ProtocolError):
        return None, None
      if packet.message_type == MessageType.SESSION_CHALLENGE:
        self._activate_key(self.pending_key)
        self.pending_key = None
    if self.comma_to_rave is None or self.rave_to_comma is None:
      return None, None

    packet = decode_packet(data, self.comma_to_rave)
    if packet.message_type == MessageType.SESSION_CHALLENGE:
      challenge = CHALLENGE_STRUCT.unpack(packet.payload)[0]
      previous = self.comma_session
      self.comma_session = packet.sender_session
      ack = Packet(MessageType.SESSION_ACK, self.pi_session, self.comma_session, 0, now_ns, challenge)
      event = "session challenge answered"
      if previous is not None and previous != self.comma_session:
        event = "new comma session detected; challenge answered"
      return encode_packet(ack, self.rave_to_comma), event
    return None, None

  def rave_state_packet(self, now_ns: int) -> bytes | None:
    if self.comma_session is None or self.rave_to_comma is None:
      return None
    left_threat = self.left_threat if self.left_lane == LaneState.OCCUPIED else ThreatLevel.NONE
    right_threat = self.right_threat if self.right_lane == LaneState.OCCUPIED else ThreatLevel.NONE
    payload = pack_rave_state(RavePayload(
      self.health,
      self.left_lane,
      self.right_lane,
      left_threat,
      right_threat,
    ))
    packet = Packet(
      MessageType.RAVE_STATE,
      self.pi_session,
      self.comma_session,
      self.tx_sequence,
      now_ns,
      payload,
    )
    self.tx_sequence = (self.tx_sequence + 1) & 0xFFFFFFFF
    self.last_valid_packet = encode_packet(packet, self.rave_to_comma)
    return self.last_valid_packet

  def restart(self) -> None:
    self.pi_session = secrets.token_bytes(16)
    self.comma_session = None
    self.tx_sequence = 0

  def forget_key(self) -> None:
    self.master_key = None
    self.pending_key = None
    self.offer = None
    self.comma_to_rave = None
    self.rave_to_comma = None
    self.restart()


def load_key(path: Path) -> tuple[str, str, bytes | None]:
  if not path.exists():
    return "rave-pi5-dev", "RAVE-Pi5", None
  data = json.loads(path.read_text(encoding="utf-8"))
  key = bytes.fromhex(data["master_key"])
  if len(key) != 32:
    raise ValueError("saved simulator pairing key has invalid length")
  return data["device_id"], data["device_name"], key


def save_key(path: Path, endpoint: PiEndpoint) -> None:
  if endpoint.master_key is None:
    return
  payload = json.dumps({
    "device_id": endpoint.device_id,
    "device_name": endpoint.device_name,
    "master_key": endpoint.master_key.hex(),
  })
  path.parent.mkdir(parents=True, exist_ok=True)
  fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
  try:
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
      f.write(payload)
      f.flush()
      os.fsync(f.fileno())
    os.replace(temporary, path)
  finally:
    if os.path.exists(temporary):
      os.unlink(temporary)


class RaveSimulator:
  def __init__(self, bind: str, comma: str, key_file: Path, log_dir: Path, local_ui: bool = False):
    self.bind = bind
    self.comma = comma
    self.key_file = key_file
    self.local_ui = local_ui
    self.journal = EventJournal(log_dir)
    self.paused = False
    self.auto_resume_ns = 0
    self.network_state = "LOCAL" if local_ui else "STARTING"
    self.network_error = ""
    self.pairing_phase = "LOCAL BYPASS" if local_ui else "WAITING"
    self.last_rx_ns = 0
    self.last_tx_ns = 0
    self.last_state_ns = 0
    self.next_network_retry_ns = 0
    self.rx_packets = 0
    self.tx_packets = 0
    self.auth_failures = 0
    self.protocol_errors = 0
    self.network_errors = 0
    self.old_session_packet: bytes | None = None
    self.tx_times: deque[int] = deque()
    self.runtime: socket.socket | None = None
    self.pairing: socket.socket | None = None
    self.local_pm = None

    if local_ui:
      from cereal import messaging
      from openpilot.system.hardware import PC
      if not PC:
        raise RuntimeError("--local-ui is desktop-only; do not create a second raveState publisher on a comma")
      self.endpoint = PiEndpoint("rave-local-ui", "RAVE Local Raylib")
      self.endpoint.comma_session = b"L" * 16
      self.endpoint.rave_to_comma = b"L" * 32
      self.local_pm = messaging.PubMaster(["raveState"])
      self.journal.add("local Raylib UI mode ready; publishing eligible synthetic raveState")
    else:
      device_id, device_name, key = load_key(key_file)
      self.endpoint = PiEndpoint(device_id, device_name, key)
      if key is not None:
        self.pairing_phase = "KEY SAVED"
        self.journal.add("saved pairing key loaded")
      else:
        self.journal.add("no saved pairing key; waiting for comma pairing request")

  @staticmethod
  def _side_scenario(lane: LaneState, threat: ThreatLevel) -> str:
    if lane == LaneState.CLEAR:
      return "CLEAR"
    return "WARNING" if threat == ThreatLevel.WARNING else "WATCH"

  @property
  def left_scenario(self) -> str:
    return self._side_scenario(self.endpoint.left_lane, self.endpoint.left_threat)

  @property
  def right_scenario(self) -> str:
    return self._side_scenario(self.endpoint.right_lane, self.endpoint.right_threat)

  @property
  def scenario(self) -> str:
    return f"L {self.left_scenario} / R {self.right_scenario}"

  @property
  def session_state(self) -> str:
    if self.local_ui:
      return "CONNECTED"
    if self.endpoint.comma_session is not None and self.endpoint.rave_to_comma is not None:
      return "CONNECTED"
    if self.endpoint.master_key is not None:
      return "WAITING CHALLENGE"
    return "UNPAIRED"

  @property
  def tx_hz(self) -> float:
    now_ns = time.monotonic_ns()
    while self.tx_times and now_ns - self.tx_times[0] > RATE_WINDOW_NS:
      self.tx_times.popleft()
    if len(self.tx_times) < 2:
      return 0.0
    span = self.tx_times[-1] - self.tx_times[0]
    return 0.0 if span <= 0 else (len(self.tx_times) - 1) * 1e9 / span

  def _set_network_down(self, error: OSError, now_ns: int) -> None:
    self._close_sockets()
    self.next_network_retry_ns = now_ns + NETWORK_RETRY_NS
    message = f"{type(error).__name__}: {error}"
    if self.network_state != "RETRYING" or message != self.network_error:
      self.journal.add(f"network unavailable; retrying automatically ({message})", "WARN")
    self.network_state = "RETRYING"
    self.network_error = message
    self.network_errors += 1

  def _close_sockets(self) -> None:
    for sock in (self.runtime, self.pairing):
      if sock is not None:
        try:
          sock.close()
        except OSError:
          pass
    self.runtime = None
    self.pairing = None

  def _ensure_network(self, now_ns: int) -> bool:
    if self.local_ui:
      return True
    if self.runtime is not None and self.pairing is not None:
      return True
    if now_ns < self.next_network_retry_ns:
      return False
    self._close_sockets()
    runtime = None
    pairing = None
    try:
      runtime = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      pairing = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      for sock, port in ((runtime, RUNTIME_PORT), (pairing, PAIRING_PORT)):
        sock.setblocking(False)
        sock.bind((self.bind, port))
      self.runtime = runtime
      self.pairing = pairing
      recovered = self.network_state == "RETRYING"
      self.network_state = "READY"
      self.network_error = ""
      if recovered:
        self.journal.add("network recovered; simulator sockets rebound")
      else:
        self.journal.add(f"network ready on {self.bind}; target comma {self.comma}")
      return True
    except OSError as e:
      if runtime is not None:
        try:
          runtime.close()
        except OSError:
          pass
      if pairing is not None:
        try:
          pairing.close()
        except OSError:
          pass
      self._set_network_down(e, now_ns)
      return False

  def _safe_send(self, sock: socket.socket | None, data: bytes, destination: tuple[str, int], now_ns: int,
                 *, count_state: bool = False) -> bool:
    if sock is None:
      return False
    try:
      sock.sendto(data, destination)
      self.last_tx_ns = now_ns
      self.tx_packets += 1
      if count_state:
        self.tx_times.append(now_ns)
      return True
    except OSError as e:
      self._set_network_down(e, now_ns)
      return False

  def _publish_local_state(self, now_ns: int) -> None:
    from cereal import messaging
    msg = messaging.new_message("raveState", valid=True)
    state = msg.raveState
    state.connectionState = "connected"
    state.health = self.endpoint.health.name.lower()
    state.leftLane = "clear" if self.endpoint.left_lane == LaneState.CLEAR else "occupied"
    state.rightLane = "clear" if self.endpoint.right_lane == LaneState.CLEAR else "occupied"
    state.leftThreat = (
      "none" if self.endpoint.left_lane == LaneState.CLEAR else
      "warning" if self.endpoint.left_threat == ThreatLevel.WARNING else "watch"
    )
    state.rightThreat = (
      "none" if self.endpoint.right_lane == LaneState.CLEAR else
      "warning" if self.endpoint.right_threat == ThreatLevel.WARNING else "watch"
    )
    state.enabled = True
    state.paired = True
    state.peerName = "RAVE Local Raylib"
    state.reason = "none"
    state.packetAgeMs = 0
    state.vehicleStateTxHz = 0.0
    state.raveStateRxHz = 10.0
    state.staleCount = 0
    state.authFailureCount = 0
    state.malformedCount = 0
    state.peerRestartCount = 0
    assert self.local_pm is not None
    self.local_pm.send("raveState", msg)
    self.last_tx_ns = now_ns
    self.tx_packets += 1
    self.tx_times.append(now_ns)

  def _handle_pairing_packet(self, data: bytes, now_ns: int) -> None:
    previous_key = self.endpoint.master_key
    response, event = self.endpoint.handle_pairing(data, now_ns)
    self.rx_packets += 1
    self.last_rx_ns = now_ns
    if event:
      self.pairing_phase = (
        "OFFER SENT" if event.startswith("pair probe") else
        "CONFIRM SENT" if event.startswith("pair key") else
        "PAIRED" if event.startswith("pairing complete") else self.pairing_phase
      )
      self.journal.add(event)
    if response is not None:
      self._safe_send(self.pairing, response, (self.comma, PAIRING_PORT), now_ns)
    if self.endpoint.master_key is not None and self.endpoint.master_key != previous_key:
      save_key(self.key_file, self.endpoint)
      self.journal.add(f"pairing key saved to {self.key_file} (key material not logged)")

  def _handle_runtime_packet(self, data: bytes, now_ns: int) -> None:
    response, event = self.endpoint.handle_runtime(data, now_ns)
    self.rx_packets += 1
    self.last_rx_ns = now_ns
    if event:
      self.journal.add(event)
    if response is not None:
      self._safe_send(self.runtime, response, (self.comma, RUNTIME_PORT), now_ns)

  def _update_auto_resume(self, now_ns: int) -> None:
    if self.auto_resume_ns and now_ns >= self.auto_resume_ns:
      self.auto_resume_ns = 0
      if self.paused:
        self.paused = False
        self.journal.add("stale-window test complete; state transmit auto-resumed")

  def step(self, timeout: float = 0.0) -> None:
    now_ns = time.monotonic_ns()
    self._update_auto_resume(now_ns)
    if self.local_ui:
      if not self.paused and now_ns - self.last_state_ns >= STATE_PERIOD_NS:
        self._publish_local_state(now_ns)
        self.last_state_ns = now_ns
      return

    if not self._ensure_network(now_ns):
      if timeout > 0:
        time.sleep(timeout)
      return

    sockets = [sock for sock in (self.runtime, self.pairing) if sock is not None]
    try:
      readable, _, _ = select.select(sockets, [], [], timeout)
    except OSError as e:
      self._set_network_down(e, now_ns)
      return

    for sock in readable:
      for _ in range(32):
        try:
          data, source = sock.recvfrom(MAX_DATAGRAM_SIZE + 1)
        except BlockingIOError:
          break
        except OSError as e:
          self._set_network_down(e, now_ns)
          break
        if source[0] != self.comma or len(data) > MAX_DATAGRAM_SIZE:
          self.protocol_errors += 1
          continue
        try:
          if sock is self.pairing:
            self._handle_pairing_packet(data, now_ns)
          else:
            self._handle_runtime_packet(data, now_ns)
        except AuthenticationError:
          self.auth_failures += 1
          self.journal.add("dropped packet with invalid authentication", "WARN")
        except (ProtocolError, ValueError) as e:
          self.protocol_errors += 1
          self.journal.add(f"dropped protocol packet: {e}", "WARN")

    now_ns = time.monotonic_ns()
    if not self.paused and now_ns - self.last_state_ns >= STATE_PERIOD_NS:
      state = self.endpoint.rave_state_packet(now_ns)
      if state is not None:
        self._safe_send(self.runtime, state, (self.comma, RUNTIME_PORT), now_ns, count_state=True)
      self.last_state_ns = now_ns

  def set_scenario(self, scenario: str, side: str = "left") -> None:
    scenario = scenario.upper()
    side = side.lower()
    if scenario == "CLEAR":
      lane, threat = LaneState.CLEAR, ThreatLevel.NONE
    elif scenario == "WATCH":
      lane, threat = LaneState.OCCUPIED, ThreatLevel.WATCH
    elif scenario == "WARNING":
      lane, threat = LaneState.OCCUPIED, ThreatLevel.WARNING
    else:
      raise ValueError(f"unknown scenario {scenario}")

    sides = ("left", "right") if side == "both" else (side,)
    if any(value not in ("left", "right") for value in sides):
      raise ValueError(f"unknown side {side}")
    for value in sides:
      setattr(self.endpoint, f"{value}_lane", lane)
      setattr(self.endpoint, f"{value}_threat", threat)
    self.journal.add(f"{side} scenario set to {scenario}")

  def set_health(self, health: str) -> None:
    health = health.upper()
    mapping = {
      "OK": RaveHealth.OK,
      "DEGRADED": RaveHealth.DEGRADED,
      "FAULT": RaveHealth.FAULT,
      "UNKNOWN": RaveHealth.UNKNOWN,
    }
    if health not in mapping:
      raise ValueError(f"unknown health {health}")
    self.endpoint.health = mapping[health]
    self.journal.add(f"RAVE health set to {health}")

  def set_paused(self, paused: bool) -> None:
    self.auto_resume_ns = 0
    if self.paused == paused:
      return
    self.paused = paused
    self.journal.add("state transmit paused; Raylib warning should fail dark" if paused else "state transmit resumed")

  def trigger_stale_test(self, duration_ms: int = 600) -> None:
    duration_ms = max(300, int(duration_ms))
    self.paused = True
    self.auto_resume_ns = time.monotonic_ns() + duration_ms * 1_000_000
    self.journal.add(f"stale-window test started: TX paused for {duration_ms} ms; warning should fail dark by 275 ms")

  def restart_session(self) -> None:
    if self.local_ui:
      self.journal.add("local UI mode does not use an authenticated runtime session", "WARN")
      return
    self.old_session_packet = self.endpoint.last_valid_packet
    self.endpoint.restart()
    self.journal.add("simulator session restarted; waiting for comma challenge")

  def forget_simulator_key(self) -> None:
    if self.local_ui:
      return
    self.endpoint.forget_key()
    try:
      self.key_file.unlink()
    except FileNotFoundError:
      pass
    self.pairing_phase = "WAITING"
    self.journal.add("simulator pairing key forgotten; forget/re-pair the device on comma too", "WARN")

  def inject_fault(self, fault: str) -> None:
    if self.local_ui:
      self.journal.add("protocol fault injection is disabled in local UI mode", "WARN")
      return
    now_ns = time.monotonic_ns()
    if not self._ensure_network(now_ns):
      self.journal.add("fault not sent: network unavailable", "WARN")
      return

    fault = fault.lower()
    if fault == "invalid-hmac":
      if self.endpoint.last_valid_packet is None:
        self.journal.add("invalid-HMAC skipped: no valid state packet exists yet", "WARN")
        return
      bad = bytearray(self.endpoint.last_valid_packet)
      bad[-1] ^= 1
      self._safe_send(self.runtime, bytes(bad), (self.comma, RUNTIME_PORT), now_ns)
    elif fault == "malformed":
      self._safe_send(self.runtime, b"RAVE-malformed", (self.comma, RUNTIME_PORT), now_ns)
    elif fault == "duplicate":
      if self.endpoint.last_valid_packet is None:
        self.journal.add("duplicate skipped: no valid state packet exists yet", "WARN")
        return
      self._safe_send(self.runtime, self.endpoint.last_valid_packet, (self.comma, RUNTIME_PORT), now_ns)
    elif fault == "out-of-order":
      self.endpoint.tx_sequence = max(0, self.endpoint.tx_sequence - 2)
    elif fault == "reset-sequence":
      self.endpoint.tx_sequence = 0
    elif fault == "old-replay":
      if self.old_session_packet is None:
        self.journal.add("old-session replay skipped: restart a live session first", "WARN")
        return
      self._safe_send(self.runtime, self.old_session_packet, (self.comma, RUNTIME_PORT), now_ns)
    elif fault == "burst":
      sent = 0
      for i in range(32):
        packet = self.endpoint.rave_state_packet(now_ns + i)
        if packet is None:
          break
        if self._safe_send(self.runtime, packet, (self.comma, RUNTIME_PORT), now_ns + i):
          sent += 1
      self.journal.add(f"burst injected: {sent} authenticated state packets")
      return
    else:
      raise ValueError(f"unknown fault {fault}")
    self.journal.add(f"fault injected: {fault}")

  def status_line(self) -> str:
    return (
      f"network={self.network_state} pairing={self.pairing_phase} session={self.session_state} "
      f"scenario=\"{self.scenario}\" health={self.endpoint.health.name} paused={self.paused} tx={self.tx_hz:.1f}Hz "
      f"rx={self.rx_packets} txPackets={self.tx_packets} authFail={self.auth_failures} protoErr={self.protocol_errors}"
    )


def run_self_test() -> int:
  now = 10_000_000_000
  endpoint = PiEndpoint("rave-self-test", "RAVE Self Test")
  comma_pairing = CommaPairing()
  comma_pairing.start(now, 10_000_000_000)

  probe = Packet(MessageType.PAIR_PROBE, ZERO_SESSION, ZERO_SESSION, 0, now, comma_pairing.probe_payload())
  offer_bytes, _ = endpoint.handle_pairing(encode_packet(probe, None), now)
  assert offer_bytes is not None
  offer_packet = decode_packet(offer_bytes, None, allow_unauthenticated=True)
  comma_pairing.accept_offer(offer_packet.payload)

  install_payload = comma_pairing.confirm_payload()
  install = Packet(MessageType.PAIR_KEY_INSTALL, ZERO_SESSION, ZERO_SESSION, 0, now + 1, install_payload)
  confirm_bytes, _ = endpoint.handle_pairing(encode_packet(install, None), now + 1)
  assert confirm_bytes is not None and comma_pairing.master_key is not None
  confirm_packet = decode_packet(confirm_bytes, comma_pairing.master_key)
  result = comma_pairing.accept_key_confirm(confirm_packet.payload)

  complete = Packet(MessageType.PAIR_COMPLETE, ZERO_SESSION, ZERO_SESSION, 0, now + 2, comma_pairing.complete_payload())
  endpoint.handle_pairing(encode_packet(complete, result.master_key), now + 2)
  assert endpoint.master_key == result.master_key

  c2r, r2c = derive_directional_keys(result.master_key)
  comma_session = CommaSession(local_session=b"C" * 16)
  challenge = encode_packet(comma_session.challenge_packet(now + 3), c2r)
  ack_bytes, _ = endpoint.handle_runtime(challenge, now + 3)
  assert ack_bytes is not None
  ack = decode_packet(ack_bytes, r2c)
  assert comma_session.accept_ack(ack)

  endpoint.left_lane = LaneState.OCCUPIED
  endpoint.left_threat = ThreatLevel.WARNING
  state_bytes = endpoint.rave_state_packet(now + 4)
  assert state_bytes is not None
  state_packet = decode_packet(state_bytes, r2c)
  comma_session.accept_runtime(state_packet)
  payload = unpack_rave_state(state_packet.payload)
  assert payload.health == RaveHealth.OK
  assert payload.left_lane == LaneState.OCCUPIED
  assert payload.left_threat == ThreatLevel.WARNING

  endpoint.restart()
  assert endpoint.comma_session is None and endpoint.tx_sequence == 0
  print("RAVE simulator self-test: PASS")
  return 0


def _age_text(last_ns: int) -> str:
  if last_ns <= 0:
    return "never"
  age = max(0.0, (time.monotonic_ns() - last_ns) / 1e9)
  return f"{age:.1f}s ago"


# RAVE_READABLE_FONTS_V1
# The stock Raylib bitmap font is intentionally not used for the working UI.
# It looked stylish at title size, but was difficult to scan in controls/logs.
_FONT_BODY = None
_FONT_BOLD = None
_FONT_MONO = None


def _resolve_font(query: str, fallbacks: tuple[str, ...]) -> str | None:
  try:
    found = subprocess.check_output(
      ["fc-match", "-f", "%{file}\n", query],
      text=True, stderr=subprocess.DEVNULL, timeout=1.0,
    ).splitlines()
    if found and Path(found[0]).is_file():
      return found[0]
  except (FileNotFoundError, subprocess.SubprocessError, OSError):
    pass
  for candidate in fallbacks:
    if Path(candidate).is_file():
      return candidate
  return None


def _load_ui_fonts() -> None:
  global _FONT_BODY, _FONT_BOLD, _FONT_MONO
  assert rl is not None

  body_path = _resolve_font("DejaVu Sans", (
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf",
  ))
  bold_path = _resolve_font("DejaVu Sans:style=Bold", (
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/liberation2/LiberationSans-Bold.ttf",
  ))
  mono_path = _resolve_font("DejaVu Sans Mono", (
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/truetype/liberation2/LiberationMono-Regular.ttf",
  ))

  # load_font keeps deployment simple and lets Raylib scale the glyph atlas.
  _FONT_BODY = rl.load_font(body_path) if body_path else rl.get_font_default()
  _FONT_BOLD = rl.load_font(bold_path) if bold_path else _FONT_BODY
  _FONT_MONO = rl.load_font(mono_path) if mono_path else _FONT_BODY


def _font(role: str = "body"):
  assert rl is not None
  if role == "bold":
    return _FONT_BOLD or rl.get_font_default()
  if role == "mono":
    return _FONT_MONO or rl.get_font_default()
  return _FONT_BODY or rl.get_font_default()


def _measure_text(text: str, size: int, role: str = "body", spacing: float = 0.35) -> float:
  assert rl is not None
  return rl.measure_text_ex(_font(role), text, size, spacing).x


def _draw_text(text: str, x: float, y: float, size: int, color, *, role: str = "body", spacing: float = 0.35) -> None:
  assert rl is not None
  rl.draw_text_ex(_font(role), text, rl.Vector2(x, y), size, spacing, color)


def _draw_card(rect, title: str) -> None:
  assert rl is not None
  rl.draw_rectangle_rounded(rect, 0.08, 12, rl.Color(19, 24, 32, 248))
  rl.draw_rectangle_rounded_lines_ex(rect, 0.08, 12, 1.0, rl.Color(255, 255, 255, 24))
  _draw_text(title, rect.x + 20, rect.y + 15, 25, rl.Color(239, 242, 247, 255), role="bold")


def _button(rect, label: str, accent, *, active: bool = False, enabled: bool = True, sublabel: str = "") -> bool:
  assert rl is not None
  mouse = rl.get_mouse_position()
  hovered = enabled and rl.check_collision_point_rec(mouse, rect)
  pressed = hovered and rl.is_mouse_button_down(rl.MouseButton.MOUSE_BUTTON_LEFT)
  if not enabled:
    fill = rl.Color(39, 43, 50, 170)
    border = rl.Color(255, 255, 255, 14)
    text = rl.Color(130, 135, 143, 255)
  else:
    alpha = 76 if active else 36
    if hovered:
      alpha += 24
    if pressed:
      alpha += 16
    fill = rl.Color(accent.r, accent.g, accent.b, alpha)
    border = rl.Color(accent.r, accent.g, accent.b, 150 if active else 80)
    text = rl.Color(245, 247, 250, 255)
  rl.draw_rectangle_rounded(rect, 0.14, 12, fill)
  rl.draw_rectangle_rounded_lines_ex(rect, 0.14, 12, 1.5, border)
  tw = _measure_text(label, 20, "bold")
  _draw_text(label, rect.x + (rect.width - tw) / 2, rect.y + 12, 20, text, role="bold")
  if sublabel:
    sw = _measure_text(sublabel, 14)
    _draw_text(sublabel, rect.x + (rect.width - sw) / 2, rect.y + 40, 14, rl.Color(text.r, text.g, text.b, 190))
  return enabled and hovered and rl.is_mouse_button_released(rl.MouseButton.MOUSE_BUTTON_LEFT)


def _status_chip(x: float, y: float, label: str, value: str, color) -> float:
  assert rl is not None
  text = f"{label}  {value}"
  width = max(180, _measure_text(text, 16, "bold") + 34)
  rect = rl.Rectangle(x, y, width, 36)
  rl.draw_rectangle_rounded(rect, 0.35, 12, rl.Color(color.r, color.g, color.b, 34))
  rl.draw_rectangle_rounded_lines_ex(rect, 0.35, 12, 1.0, rl.Color(color.r, color.g, color.b, 95))
  _draw_text(text, x + 16, y + 8, 16, rl.Color(240, 243, 247, 255), role="bold")
  return x + width + 10


def run_gui(sim: RaveSimulator) -> int:
  if rl is None:
    raise RuntimeError("pyray is not available; use the prepared StarPilot host runtime or --headless")

  rl.set_config_flags(rl.ConfigFlags.FLAG_WINDOW_RESIZABLE | rl.ConfigFlags.FLAG_VSYNC_HINT)
  rl.init_window(GUI_WIDTH, GUI_HEIGHT, "RAVE Simulator • Raylib Control Console")
  _load_ui_fonts()
  rl.set_target_fps(60)
  forget_arm_until = 0.0

  amber = rl.Color(255, 179, 0, 255)
  red = rl.Color(255, 59, 48, 255)
  green = rl.Color(52, 199, 89, 255)
  blue = rl.Color(64, 156, 255, 255)
  purple = rl.Color(175, 82, 222, 255)
  muted = rl.Color(142, 148, 156, 255)

  try:
    while not rl.window_should_close():
      sim.step(0.0)

      # Keyboard shortcuts remain available, but every action is also visible and clickable.
      if rl.is_key_pressed(rl.KeyboardKey.KEY_ONE):
        sim.set_scenario("WATCH")
      if rl.is_key_pressed(rl.KeyboardKey.KEY_TWO):
        sim.set_scenario("WARNING")
      if rl.is_key_pressed(rl.KeyboardKey.KEY_THREE):
        sim.set_scenario("CLEAR")
      if rl.is_key_pressed(rl.KeyboardKey.KEY_FOUR):
        sim.set_scenario("WATCH", "right")
      if rl.is_key_pressed(rl.KeyboardKey.KEY_FIVE):
        sim.set_scenario("WARNING", "right")
      if rl.is_key_pressed(rl.KeyboardKey.KEY_SIX):
        sim.set_scenario("CLEAR", "right")
      if rl.is_key_pressed(rl.KeyboardKey.KEY_SPACE):
        sim.set_paused(not sim.paused)
      if rl.is_key_pressed(rl.KeyboardKey.KEY_R):
        sim.restart_session()

      width = max(1100, rl.get_screen_width())
      height = max(720, rl.get_screen_height())
      margin = 26
      header_h = 96
      content_y = header_h + 10
      top_h = min(420, max(400, height * 0.50))
      gap = 16
      col1 = max(320, (width - margin * 2 - gap * 2) * 0.30)
      col2 = max(360, (width - margin * 2 - gap * 2) * 0.34)
      col3 = width - margin * 2 - gap * 2 - col1 - col2

      rl.begin_drawing()
      rl.clear_background(rl.Color(8, 11, 16, 255))

      _draw_text("RAVE Simulator", margin, 18, 36, rl.Color(248, 250, 252, 255), role="bold")
      mode = "LOCAL RAYLIB" if sim.local_ui else "C3X NETWORK"
      _draw_text(f"Raylib Control Console  •  {mode}", margin, 60, 18, rl.Color(169, 176, 186, 255))

      chip_x = max(510, width * 0.43)
      net_color = green if sim.network_state in ("READY", "LOCAL") else red
      chip_x = _status_chip(chip_x, 27, "NETWORK", sim.network_state, net_color)
      pair_color = green if sim.pairing_phase in ("PAIRED", "KEY SAVED", "LOCAL BYPASS") else amber
      chip_x = _status_chip(chip_x, 27, "PAIRING", sim.pairing_phase, pair_color)
      sess_color = green if sim.session_state == "CONNECTED" else amber
      _status_chip(chip_x, 27, "SESSION", sim.session_state, sess_color)

      scenario_rect = rl.Rectangle(margin, content_y, col1, top_h)
      status_rect = rl.Rectangle(margin + col1 + gap, content_y, col2, top_h)
      fault_rect = rl.Rectangle(margin + col1 + gap + col2 + gap, content_y, col3, top_h)
      _draw_card(scenario_rect, "Scenario Control")
      _draw_card(status_rect, "Live Status")
      _draw_card(fault_rect, "Fault Injection")

      sx = scenario_rect.x + 20
      sw = scenario_rect.width - 40
      sy = scenario_rect.y + 58
      _draw_text("LEFT", sx, sy, 16, rl.Color(176, 182, 191, 255), role="bold")
      sy += 20
      third = (sw - 16) / 3
      for index, (label, color) in enumerate((("WATCH", amber), ("WARNING", red), ("CLEAR", green))):
        if _button(rl.Rectangle(sx + index * (third + 8), sy, third, 48), label, color,
                   active=sim.left_scenario == label):
          sim.set_scenario(label, "left")
      sy += 62
      _draw_text("RIGHT", sx, sy, 16, rl.Color(176, 182, 191, 255), role="bold")
      sy += 20
      for index, (label, color) in enumerate((("WATCH", amber), ("WARNING", red), ("CLEAR", green))):
        if _button(rl.Rectangle(sx + index * (third + 8), sy, third, 48), label, color,
                   active=sim.right_scenario == label):
          sim.set_scenario(label, "right")
      sy += 62
      if _button(rl.Rectangle(sx, sy, sw, 36), "CLEAR BOTH SIDES", green,
                 active=sim.left_scenario == "CLEAR" and sim.right_scenario == "CLEAR"):
        sim.set_scenario("CLEAR", "both")
      sy += 47
      _draw_text("HEALTH", sx, sy, 16, rl.Color(176, 182, 191, 255), role="bold")
      sy += 20
      health_gap = 7
      health_w = (sw - health_gap * 2) / 3
      for index, (label, color) in enumerate((("OK", green), ("DEGRADED", amber), ("FAULT", red))):
        if _button(rl.Rectangle(sx + index * (health_w + health_gap), sy, health_w, 40), label, color,
                   active=sim.endpoint.health.name == label):
          sim.set_health(label)
      sy += 51
      third_action = (sw - 16) / 3
      pause_label = "RESUME" if sim.paused and not sim.auto_resume_ns else "PAUSE"
      if _button(rl.Rectangle(sx, sy, third_action, 44), pause_label, blue, active=sim.paused and not sim.auto_resume_ns):
        sim.set_paused(not sim.paused)
      if _button(rl.Rectangle(sx + third_action + 8, sy, third_action, 44), "STALE 600ms", amber, active=bool(sim.auto_resume_ns)):
        sim.trigger_stale_test()
      if _button(rl.Rectangle(sx + 2 * (third_action + 8), sy, third_action, 44), "RESTART", purple, enabled=not sim.local_ui):
        sim.restart_session()

      tx_state = "PAUSED" if sim.paused else f"{sim.tx_hz:.1f} Hz"
      eligible_preview = (sim.session_state == "CONNECTED" and not sim.paused and
                          sim.endpoint.health in (RaveHealth.OK, RaveHealth.DEGRADED))
      lines = [
        ("Mode", mode),
        ("Health", sim.endpoint.health.name),
        ("Left state", sim.left_scenario),
        ("Right state", sim.right_scenario),
        ("Expected UI", "ACTIVE" if eligible_preview else "FAIL-DARK"),
        ("State TX", tx_state),
        ("Last RX", _age_text(sim.last_rx_ns)),
        ("Last TX", _age_text(sim.last_tx_ns)),
        ("Packets", f"RX {sim.rx_packets} / TX {sim.tx_packets}"),
        ("Errors", f"Auth {sim.auth_failures} / Proto {sim.protocol_errors} / Net {sim.network_errors}"),
      ]
      if not sim.local_ui:
        lines.insert(1, ("Target", f"{sim.comma}:{RUNTIME_PORT}"))
        lines.insert(2, ("Bind", f"{sim.bind}:{RUNTIME_PORT}"))
      y = status_rect.y + 62
      for label, value in lines:
        _draw_text(label, status_rect.x + 20, y, 17, rl.Color(166, 173, 183, 255))
        value_w = _measure_text(value, 17, "bold")
        _draw_text(value, status_rect.x + status_rect.width - 20 - value_w, y, 17, rl.Color(242, 245, 249, 255), role="bold")
        y += 26

      # Small preview makes the simulator state obvious before looking at the C3X.
      preview_w = min(250.0, status_rect.width - 40)
      preview_h = 76.0
      preview_x = status_rect.x + (status_rect.width - preview_w) / 2
      preview_y = status_rect.y + status_rect.height - preview_h - 18
      preview = rl.Rectangle(preview_x, preview_y, preview_w, preview_h)
      rl.draw_rectangle_rounded(preview, 0.12, 10, rl.Color(5, 7, 10, 255))
      rl.draw_rectangle_rounded_lines_ex(preview, 0.12, 10, 1.0, rl.Color(255, 255, 255, 30))
      if eligible_preview:
        def preview_side(side: str, scenario: str) -> None:
          if scenario == "CLEAR":
            return
          width_px = 12 if scenario == "WARNING" else 6
          color = red if scenario == "WARNING" else amber
          x = int(preview.x if side == "left" else preview.x + preview.width - width_px)
          rl.draw_rectangle(x, int(preview.y), width_px, int(preview.height), color)
        preview_side("left", sim.left_scenario)
        preview_side("right", sim.right_scenario)
      label = "EXPECTED C3X EDGE OUTPUT" if eligible_preview else "FAIL-DARK EXPECTED"
      lw = _measure_text(label, 13, "bold")
      _draw_text(label, preview.x + (preview.width - lw) / 2, preview.y + preview.height / 2 - 7, 13, muted, role="bold")

      fx = fault_rect.x + 20
      fw = fault_rect.width - 40
      fy = fault_rect.y + 58
      fault_buttons = [
        ("BAD HMAC", "invalid-hmac"),
        ("MALFORMED", "malformed"),
        ("DUPLICATE", "duplicate"),
        ("OUT OF ORDER", "out-of-order"),
        ("RESET SEQUENCE", "reset-sequence"),
        ("OLD SESSION REPLAY", "old-replay"),
        ("32-PACKET BURST", "burst"),
      ]
      small_h = 38
      for label, command in fault_buttons:
        if _button(rl.Rectangle(fx, fy, fw, small_h), label, purple, enabled=not sim.local_ui):
          sim.inject_fault(command)
        fy += small_h + 5

      log_y = content_y + top_h + gap
      log_h = max(190, height - log_y - margin)
      log_rect = rl.Rectangle(margin, log_y, width - margin * 2, log_h)
      _draw_card(log_rect, "Event Log")
      log_path = str(sim.journal.text_path)
      _draw_text(f"Logs: {log_path}", log_rect.x + 20, log_rect.y + 50, 15, rl.Color(163, 170, 180, 255), role="mono")

      max_events = max(2, int((log_h - 122) // 27))
      events = list(sim.journal.events)[-max_events:]
      ey = log_rect.y + 80
      for event in events:
        stamp = time.strftime("%H:%M:%S", time.localtime(event.when))
        level_color = red if event.level == "WARN" else rl.Color(114, 186, 255, 255)
        _draw_text(stamp, log_rect.x + 20, ey, 16, rl.Color(166, 173, 183, 255), role="mono")
        _draw_text(event.level, log_rect.x + 108, ey, 16, level_color, role="mono")
        _draw_text(event.message[:122], log_rect.x + 180, ey, 16, rl.Color(231, 235, 240, 255), role="mono")
        ey += 27

      # Destructive action is deliberately two-click armed.
      if not sim.local_ui:
        forget_w = 176
        forget_rect = rl.Rectangle(log_rect.x + log_rect.width - forget_w - 20, log_rect.y + 16, forget_w, 42)
        armed = time.monotonic() < forget_arm_until
        label = "CONFIRM FORGET" if armed else "FORGET SIM KEY"
        if _button(forget_rect, label, red, active=armed):
          if armed:
            sim.forget_simulator_key()
            forget_arm_until = 0.0
          else:
            forget_arm_until = time.monotonic() + 3.0
            sim.journal.add("forget-key armed for 3 seconds; click again to confirm", "WARN")

      _draw_text("Shortcuts: 1/2/3 Left Watch/Warning/Clear  •  4/5/6 Right  •  Space Pause  •  R Restart",
                 log_rect.x + 20, log_rect.y + log_rect.height - 28, 15, rl.Color(166, 173, 183, 255), role="mono")
      rl.end_drawing()
  finally:
    rl.close_window()
    sim._close_sockets()
  return 0


def run_headless(sim: RaveSimulator) -> int:
  print("RAVE simulator headless mode")
  print("Commands: watch warning clear | right-watch right-warning right-clear | clear-all")
  print("          health-ok health-degraded health-fault | pause resume stale restart status")
  print("          invalid-hmac malformed duplicate out-of-order reset-sequence old-replay burst | forget-key quit")
  print(sim.status_line())
  last_summary = time.monotonic()
  while True:
    sim.step(0.05)
    readable, _, _ = select.select([sys.stdin], [], [], 0)
    if readable:
      line = sys.stdin.readline()
      if line == "":
        return 0
      command = line.strip().lower()
      if command in ("watch", "warning", "clear"):
        sim.set_scenario(command, "left")
      elif command in ("right-watch", "right-warning", "right-clear"):
        sim.set_scenario(command.removeprefix("right-"), "right")
      elif command == "clear-all":
        sim.set_scenario("clear", "both")
      elif command in ("health-ok", "health-degraded", "health-fault"):
        sim.set_health(command.removeprefix("health-"))
      elif command == "pause":
        sim.set_paused(True)
      elif command == "resume":
        sim.set_paused(False)
      elif command == "stale":
        sim.trigger_stale_test()
      elif command == "restart":
        sim.restart_session()
      elif command == "status":
        print(sim.status_line())
      elif command in ("invalid-hmac", "malformed", "duplicate", "out-of-order", "reset-sequence", "old-replay", "burst"):
        sim.inject_fault(command)
      elif command == "forget-key":
        sim.forget_simulator_key()
      elif command in ("quit", "exit"):
        return 0
      elif command:
        print(f"Unknown command: {command}")
    if time.monotonic() - last_summary >= 5.0:
      print(sim.status_line())
      last_summary = time.monotonic()


def main() -> int:
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--bind", default=RAVE_ADDRESS, help="RAVE host IPv4 address (default: %(default)s)")
  parser.add_argument("--comma", default=COMMA_ADDRESS, help="comma RAVE IPv4 address (default: %(default)s)")
  parser.add_argument("--key-file", type=Path, default=Path("rave_pairing.json"), help="persistent simulator pairing credential")
  parser.add_argument("--log-dir", type=Path, default=Path.home() / ".local" / "state" / "rave-sim")
  parser.add_argument("--headless", action="store_true", help="use the legacy terminal command interface instead of the Raylib console")
  parser.add_argument("--local-ui", action="store_true", help="desktop-only: publish raveState directly for Raylib UI visual testing")
  parser.add_argument("--self-test", action="store_true", help="run an in-process pairing/session/state protocol self-test and exit")
  args = parser.parse_args()

  if args.self_test:
    return run_self_test()

  sim = RaveSimulator(args.bind, args.comma, args.key_file, args.log_dir, local_ui=args.local_ui)
  if args.headless:
    return run_headless(sim)
  return run_gui(sim)


if __name__ == "__main__":
  raise SystemExit(main())
