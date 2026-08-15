from __future__ import annotations

from dataclasses import dataclass, replace
import select
import socket
import time

from openpilot.common.params import Params
from openpilot.starpilot.system.rave_linkd.constants import (
  COMMA_ADDRESS, LaneState, MAX_DATAGRAM_SIZE, MAX_RECEIVE_DRAIN, MessageType,
  PAIRING_PORT, PAIRING_PROBE_HZ, PAIRING_WINDOW_NS, RAVE_ADDRESS, RUNTIME_PORT,
  RaveHealth, SESSION_CHALLENGE_HZ, STALE_NS, STATUS_HEARTBEAT_HZ, ThreatLevel,
  WAITING_NS, ZERO_SESSION,
)
from openpilot.starpilot.system.rave_linkd.pairing import CommaPairing
from openpilot.starpilot.system.rave_linkd.protocol import (
  AuthenticationError, Packet, ProtocolError, decode_packet, derive_directional_keys,
  encode_packet, unpack_rave_state,
)
from openpilot.starpilot.system.rave_linkd.session import CommaSession, SequenceError

RUNTIME_DESTINATION = (RAVE_ADDRESS, RUNTIME_PORT)
PAIRING_DESTINATION = (RAVE_ADDRESS, PAIRING_PORT)
@dataclass(frozen=True)
class LinkState:
  connection: str = "disabled"
  health: str = "unknown"
  left_lane: str = "unknown"
  right_lane: str = "unknown"
  left_threat: str = "none"
  right_threat: str = "none"
  reason: str = "none"


class RaveLinkCore:
  def __init__(self, now_ns: int | None = None):
    now_ns = time.monotonic_ns() if now_ns is None else now_ns
    self.session = CommaSession()
    self.pairing = CommaPairing()
    self.enabled = False
    self.peer_id = ""
    self.peer_name = ""
    self.master_key: bytes | None = None
    self.comma_to_rave: bytes | None = None
    self.rave_to_comma: bytes | None = None
    self.state = LinkState()
    self.last_rave_state_ns: int | None = None
    self.last_connected_ns: int | None = None
    self.previous_remote_session: bytes | None = None
    self.stale_count = 0
    self.auth_failures = 0
    self.malformed = 0
    self.peer_restarts = 0
    self.rave_packets = 0
    self.started_ns = now_ns

  @property
  def paired(self) -> bool:
    return bool(self.peer_id and self.master_key is not None and len(self.master_key) == 32)

  def configure(self, enabled: bool, peer_id: str = "", peer_name: str = "", master_key: bytes | None = None) -> None:
    self.enabled = enabled
    self.peer_id = peer_id
    self.peer_name = peer_name
    self.master_key = master_key if master_key and len(master_key) == 32 else None
    if self.master_key is not None:
      self.comma_to_rave, self.rave_to_comma = derive_directional_keys(self.master_key)
    else:
      self.comma_to_rave = self.rave_to_comma = None
    self.invalidate_runtime()
    if not enabled:
      self.pairing.cancel()
      self.state = LinkState(connection="disabled")
    elif not self.paired:
      self.state = LinkState(connection="notPaired", reason="notPaired")
    else:
      self.state = LinkState(connection="waiting")

  def invalidate_runtime(self) -> None:
    if self.session.remote_session is not None:
      self.previous_remote_session = self.session.remote_session
    self.session.new_attempt()
    self.last_rave_state_ns = None
    self.state = replace(self.state, health="unknown", left_lane="unknown", right_lane="unknown",
                         left_threat="none", right_threat="none")

  def start_pairing(self, now_ns: int) -> bool:
    if not self.enabled:
      return False
    self.pairing.start(now_ns, PAIRING_WINDOW_NS)
    self.invalidate_runtime()
    self.state = LinkState(connection="pairing")
    return True

  def cancel_pairing(self) -> None:
    self.pairing.cancel()
    self.state = LinkState(connection="waiting" if self.paired else "notPaired",
                           reason="none" if self.paired else "notPaired")

  def forget(self) -> None:
    self.pairing.cancel()
    self.peer_id = self.peer_name = ""
    self.master_key = self.comma_to_rave = self.rave_to_comma = None
    self.invalidate_runtime()
    self.state = LinkState(connection="notPaired", reason="notPaired") if self.enabled else LinkState()

  def make_challenge(self, now_ns: int) -> bytes | None:
    if self.pairing.active or not self.enabled or not self.paired or self.session.established or self.comma_to_rave is None:
      return None
    return encode_packet(self.session.challenge_packet(now_ns), self.comma_to_rave)

  def handle_runtime(self, data: bytes, now_ns: int) -> bool:
    if self.pairing.active or self.rave_to_comma is None:
      return False
    try:
      packet = decode_packet(data, self.rave_to_comma)
      if packet.message_type == MessageType.SESSION_ACK:
        old_remote = self.previous_remote_session
        if not self.session.accept_ack(packet):
          raise ProtocolError("invalid session acknowledgement")
        if old_remote is not None and old_remote != self.session.remote_session:
          self.peer_restarts += 1
        if self.state.connection != "stale":
          self.state = replace(self.state, connection="waiting", reason="none")
        return True
      if packet.message_type != MessageType.RAVE_STATE:
        raise ProtocolError("unexpected Pi runtime message")
      self.session.accept_runtime(packet)
      rave = unpack_rave_state(packet.payload)
      health = RaveHealth(rave.health).name.lower()
      left_lane = LaneState(rave.left_lane).name.lower()
      right_lane = LaneState(rave.right_lane).name.lower()
      left_threat = ThreatLevel(rave.left_threat).name.lower()
      right_threat = ThreatLevel(rave.right_threat).name.lower()
      if rave.health in (RaveHealth.UNKNOWN, RaveHealth.FAULT):
        left_lane = right_lane = "unknown"
        left_threat = right_threat = "none"
      self.last_rave_state_ns = self.last_connected_ns = now_ns
      self.rave_packets += 1
      self.state = LinkState("connected", health, left_lane, right_lane, left_threat, right_threat,
                             "peerFault" if health in ("fault", "unknown") else "none")
      return True
    except AuthenticationError:
      self.auth_failures += 1
    except (ProtocolError, SequenceError, ValueError):
      self.malformed += 1
    return False

  def update_freshness(self, now_ns: int) -> bool:
    old = self.state
    if not self.enabled:
      self.state = LinkState(connection="disabled")
    elif self.pairing.active:
      if self.pairing.expire(now_ns):
        self.state = LinkState(connection="waiting" if self.paired else "notPaired",
                               reason="none" if self.paired else "notPaired")
    elif not self.paired:
      self.state = LinkState(connection="notPaired", reason="notPaired")
    elif self.last_rave_state_ns is not None and now_ns - self.last_rave_state_ns > STALE_NS:
      self.stale_count += 1
      self.last_connected_ns = self.last_rave_state_ns
      self.invalidate_runtime()
      self.state = LinkState(connection="stale")
    elif self.state.connection == "stale" and self.last_connected_ns is not None and now_ns - self.last_connected_ns > WAITING_NS:
      self.state = LinkState(connection="waiting")
    return old != self.state

class RaveLinkDaemon:
  TRANSIENT_COMMANDS = ("RavePairRequest", "RavePairConfirm", "RavePairCancel", "RaveForgetRequest")

  def __init__(self, socket_factory=None):
    from cereal import messaging
    from openpilot.common.swaglog import cloudlog
    self.cloudlog = cloudlog
    self.messaging = messaging
    self.params = Params()
    self.params_memory = Params(memory=True)
    self.pm = messaging.PubMaster(["raveState"])
    self.core = RaveLinkCore()
    self._socket_factory = socket_factory or self._make_socket
    self.runtime_socket: socket.socket | None = None
    self.pairing_socket: socket.socket | None = None
    self.next_network_retry_ns = 0
    self.last_status_ns = self.last_probe_ns = self.last_challenge_ns = 0
    self.last_command_ns = self.last_config_ns = self.last_metrics_ns = 0
    self.last_metric_rave_packets = 0
    self.last_published_state: LinkState | None = None
    self.rave_rx_hz = 0.0
    self._clear_transient_commands()
    self._load_config()

  @staticmethod
  def _make_socket(port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    sock.setblocking(False)
    sock.bind((COMMA_ADDRESS, port))
    return sock

  def _clear_transient_commands(self) -> None:
    for key in self.TRANSIENT_COMMANDS:
      self.params_memory.remove(key)

  def _close_sockets(self) -> None:
    for sock in (self.runtime_socket, self.pairing_socket):
      if sock is not None:
        sock.close()
    self.runtime_socket = self.pairing_socket = None

  def _network_unavailable(self, now_ns: int) -> None:
    self._close_sockets()
    self.next_network_retry_ns = now_ns + 1_000_000_000
    self.core.state = LinkState(connection="error", reason="networkUnavailable")

  def _ensure_network(self, now_ns: int) -> bool:
    if not self.core.enabled:
      self._close_sockets()
      return False
    if self.runtime_socket is not None and self.pairing_socket is not None:
      return True
    if now_ns < self.next_network_retry_ns:
      return False
    self._close_sockets()
    try:
      self.runtime_socket = self._socket_factory(RUNTIME_PORT)
      self.pairing_socket = self._socket_factory(PAIRING_PORT)
      if self.core.state.reason == "networkUnavailable":
        self.core.state = LinkState(connection="waiting" if self.core.paired else "notPaired",
                                    reason="none" if self.core.paired else "notPaired")
      return True
    except OSError:
      self._network_unavailable(now_ns)
      return False

  def _sendto(self, sock: socket.socket | None, data: bytes, destination: tuple[str, int], now_ns: int) -> bool:
    if sock is None:
      return False
    try:
      sock.sendto(data, destination)
      return True
    except OSError:
      self._network_unavailable(now_ns)
      return False

  def _wait_for_io(self, sockets: list[socket.socket], timeout: float, now_ns: int) -> list[socket.socket]:
    if not sockets:
      time.sleep(timeout)
      return []
    try:
      readable, _, _ = select.select(sockets, [], [], timeout)
      return readable
    except OSError:
      self._network_unavailable(now_ns)
      return []

  def _pairing_allowed(self) -> bool:
    return self.params.get_bool("IsOffroad") and not self.params.get_bool("IsOnroad")

  def _enforce_pairing_state(self, now_ns: int | None = None) -> None:
    if not self.core.pairing.active:
      return
    if (now_ns is not None and self.core.pairing.expire(now_ns)) or not self._pairing_allowed():
      self.core.cancel_pairing()

  def _load_config(self) -> None:
    self.core.configure(self.params.get_bool("RaveEnabled"), self.params.get("RavePeerId") or "",
                        self.params.get("RavePeerName") or "", self.params.get("RavePairingKey"))

  def _consume_commands(self, now_ns: int) -> None:
    active = {key for key in self.TRANSIENT_COMMANDS if self.params_memory.get_bool(key)}
    for key in active:
      self.params_memory.remove(key)
    if "RaveForgetRequest" in active:
      for key in ("RavePeerId", "RavePeerName", "RavePairingKey"):
        self.params.remove(key)
      self.core.forget()
    if "RavePairCancel" in active:
      self.core.cancel_pairing()
    if "RavePairRequest" in active:
      if self._pairing_allowed():
        self.core.start_pairing(now_ns)
      else:
        self.cloudlog.warning("RAVE pairing request rejected: device is not unambiguously offroad")
    self._enforce_pairing_state(now_ns)
    if "RavePairConfirm" in active and self._pairing_allowed() and self.core.pairing.candidate is not None:
      payload = self.core.pairing.confirm_payload()
      packet = Packet(MessageType.PAIR_KEY_INSTALL, ZERO_SESSION, ZERO_SESSION, 0, now_ns, payload)
      self._sendto(self.pairing_socket, encode_packet(packet, None), PAIRING_DESTINATION, now_ns)

  def _drain(self, sock: socket.socket, pairing: bool, now_ns: int) -> None:
    for _ in range(MAX_RECEIVE_DRAIN):
      try:
        data, source = sock.recvfrom(MAX_DATAGRAM_SIZE + 1)
      except BlockingIOError:
        break
      except OSError:
        self._network_unavailable(now_ns)
        return
      if source[0] != RAVE_ADDRESS or len(data) > MAX_DATAGRAM_SIZE:
        self.core.malformed += 1
        continue
      if pairing:
        self._handle_pairing(data, now_ns)
      else:
        self.core.handle_runtime(data, now_ns)

  def _handle_pairing(self, data: bytes, now_ns: int) -> None:
    self._enforce_pairing_state(now_ns)
    if not self.core.pairing.active:
      return
    try:
      try:
        packet = decode_packet(data, None, allow_unauthenticated=True)
      except AuthenticationError:
        pairing_key = self.core.pairing.master_key
        if pairing_key is None:
          raise
        packet = decode_packet(data, pairing_key)
      if packet.message_type == MessageType.PAIR_OFFER:
        self.core.pairing.accept_offer(packet.payload)
      elif packet.message_type == MessageType.PAIR_KEY_CONFIRM and self.core.pairing.master_key is not None:
        packet = decode_packet(data, self.core.pairing.master_key)
        result = self.core.pairing.accept_key_confirm(packet.payload)
        self.params.put("RavePeerId", result.device_id)
        self.params.put("RavePeerName", result.device_name)
        self.params.put("RavePairingKey", result.master_key)
        complete = Packet(MessageType.PAIR_COMPLETE, ZERO_SESSION, ZERO_SESSION, 0, now_ns,
                          self.core.pairing.complete_payload())
        self._sendto(self.pairing_socket, encode_packet(complete, result.master_key), PAIRING_DESTINATION, now_ns)
        self.core.pairing.cancel()
        self._load_config()
    except AuthenticationError:
      self.core.auth_failures += 1
    except (ProtocolError, ValueError):
      self.core.malformed += 1

  def _publish(self, now_ns: int) -> None:
    msg = self.messaging.new_message("raveState", valid=True)
    state = msg.raveState
    s = self.core.state
    state.connectionState = s.connection
    state.health = s.health
    state.leftLane = s.left_lane
    state.rightLane = s.right_lane
    state.leftThreat = s.left_threat
    state.rightThreat = s.right_threat
    state.enabled = self.core.enabled
    state.paired = self.core.paired
    state.peerName = (self.core.pairing.candidate.device_name
                      if self.core.pairing.active and self.core.pairing.candidate is not None
                      else self.core.peer_name)
    state.reason = s.reason
    state.packetAgeMs = min(65535, 65535 if self.core.last_rave_state_ns is None else
                            (now_ns - self.core.last_rave_state_ns) // 1_000_000)
    state.vehicleStateTxHz = 0.0
    state.raveStateRxHz = self.rave_rx_hz
    state.staleCount = self.core.stale_count
    state.authFailureCount = self.core.auth_failures
    state.malformedCount = self.core.malformed
    state.peerRestartCount = self.core.peer_restarts
    self.pm.send("raveState", msg)
    self.last_status_ns = now_ns
    self.last_published_state = s

  def run(self) -> None:
    while True:
      now_ns = time.monotonic_ns()
      if now_ns - self.last_command_ns >= 100_000_000:
        self._consume_commands(now_ns)
        self.last_command_ns = now_ns
      if now_ns - self.last_config_ns >= 1_000_000_000:
        enabled = self.params.get_bool("RaveEnabled")
        if enabled != self.core.enabled:
          self._load_config()
        self.last_config_ns = now_ns

      network_ready = self._ensure_network(now_ns)
      select_timeout = 0.02 if network_ready else 0.1
      sockets = [sock for sock in (self.runtime_socket, self.pairing_socket) if sock is not None]
      readable = self._wait_for_io(sockets, select_timeout, now_ns)
      now_ns = time.monotonic_ns()
      self._enforce_pairing_state(now_ns)
      for sock in readable:
        self._drain(sock, sock is self.pairing_socket, now_ns)
      network_ready = self.runtime_socket is not None and self.pairing_socket is not None

      if network_ready and self.core.pairing.active and now_ns - self.last_probe_ns >= int(1e9 / PAIRING_PROBE_HZ):
        if self.core.pairing.master_key is not None and self.core.pairing.candidate is not None:
          message_type = MessageType.PAIR_KEY_INSTALL
          payload = self.core.pairing.confirm_payload()
        else:
          message_type = MessageType.PAIR_PROBE
          payload = self.core.pairing.probe_payload()
        packet = Packet(message_type, ZERO_SESSION, ZERO_SESSION, 0, now_ns, payload)
        self._sendto(self.pairing_socket, encode_packet(packet, None), PAIRING_DESTINATION, now_ns)
        self.last_probe_ns = now_ns
      if network_ready and now_ns - self.last_challenge_ns >= int(1e9 / SESSION_CHALLENGE_HZ):
        challenge = self.core.make_challenge(now_ns)
        if challenge is not None:
          self._sendto(self.runtime_socket, challenge, RUNTIME_DESTINATION, now_ns)
        self.last_challenge_ns = now_ns
      semantic_changed = self.core.update_freshness(now_ns)
      if now_ns - self.last_metrics_ns >= 1_000_000_000:
        if self.last_metrics_ns:
          elapsed_s = (now_ns - self.last_metrics_ns) / 1e9
          self.rave_rx_hz = (self.core.rave_packets - self.last_metric_rave_packets) / elapsed_s
        self.last_metric_rave_packets = self.core.rave_packets
        self.last_metrics_ns = now_ns
      heartbeat_hz = STATUS_HEARTBEAT_HZ if self.core.enabled else 1.0
      if semantic_changed or self.core.state != self.last_published_state or \
         now_ns - self.last_status_ns >= int(1e9 / heartbeat_hz):
        self._publish(now_ns)


def main() -> None:
  RaveLinkDaemon().run()


if __name__ == "__main__":
  main()
