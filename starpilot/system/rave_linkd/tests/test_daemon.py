from types import SimpleNamespace
from unittest.mock import patch
import socket
import unittest

from openpilot.starpilot.system.rave_linkd.constants import (
  MAX_RECEIVE_DRAIN, LaneState, MessageType, RaveHealth, ThreatLevel, VehicleFlags,
)
from openpilot.starpilot.system.rave_linkd.protocol import (
  Packet, RavePayload, SESSION_ACK_STRUCT, decode_packet, encode_packet, pack_rave_state,
  unpack_vehicle_state,
)
from openpilot.starpilot.system.rave_linkd.rave_linkd import RaveLinkCore, RaveLinkDaemon
from openpilot.tools.rave.rave_sim import PiEndpoint


MASTER = bytes(range(32))


def establish(core: RaveLinkCore, pi_session: bytes = b"p" * 16) -> None:
  ack = Packet(MessageType.SESSION_ACK, pi_session, core.session.local_session, 0, 1,
               SESSION_ACK_STRUCT.pack(core.session.challenge))
  assert core.rave_to_comma is not None
  assert core.handle_runtime(encode_packet(ack, core.rave_to_comma), 1)


def rave_packet(core: RaveLinkCore, sequence: int, left_threat=ThreatLevel.WARNING, pi_session=b"p" * 16,
                health=RaveHealth.OK) -> bytes:
  assert core.rave_to_comma is not None
  payload = pack_rave_state(RavePayload(health, LaneState.OCCUPIED, LaneState.CLEAR, left_threat, 0))
  return encode_packet(Packet(MessageType.RAVE_STATE, pi_session, core.session.local_session,
                              sequence, 2, payload), core.rave_to_comma)


class TestDaemonCore(unittest.TestCase):
  def setUp(self):
    self.core = RaveLinkCore(now_ns=0)
    self.core.configure(True, "pi-id", "RAVE-Pi5", MASTER)

  def test_handshake_alone_not_connected(self):
    establish(self.core)
    self.assertEqual(self.core.state.connection, "waiting")
    self.assertIsNone(self.core.make_challenge(3))

  def test_fresh_stale_waiting_and_recovery(self):
    establish(self.core)
    self.assertTrue(self.core.handle_runtime(rave_packet(self.core, 0), 100))
    self.assertEqual(self.core.state.connection, "connected")
    self.assertFalse(self.core.update_freshness(150_000_100))
    self.assertTrue(self.core.update_freshness(150_000_101))
    self.assertEqual(self.core.state.connection, "stale")
    self.assertEqual(self.core.state.left_threat, "none")
    self.assertFalse(self.core.session.established)
    self.core.update_freshness(2_000_000_101)
    self.assertEqual(self.core.state.connection, "waiting")
    establish(self.core, b"q" * 16)
    self.assertEqual(self.core.state.connection, "waiting")
    self.assertTrue(self.core.handle_runtime(rave_packet(self.core, 0, pi_session=b"q" * 16), 2_100_000_000))
    self.assertEqual(self.core.state.connection, "connected")

  def test_auth_failure_cannot_change_semantics(self):
    establish(self.core)
    self.core.handle_runtime(rave_packet(self.core, 0), 100)
    before = self.core.state
    bad = bytearray(rave_packet(self.core, 1, ThreatLevel.NONE))
    bad[-1] ^= 1
    self.assertFalse(self.core.handle_runtime(bytes(bad), 101))
    self.assertEqual(self.core.state, before)
    self.assertEqual(self.core.auth_failures, 1)

  def test_replayed_ack_cannot_reset_sequence_or_semantic_state(self):
    original_ack = Packet(MessageType.SESSION_ACK, b"p" * 16, self.core.session.local_session, 0, 1,
                          SESSION_ACK_STRUCT.pack(self.core.session.challenge))
    encoded_ack = encode_packet(original_ack, self.core.rave_to_comma)
    self.assertTrue(self.core.handle_runtime(encoded_ack, 1))
    state_packet = rave_packet(self.core, 100)
    self.assertTrue(self.core.handle_runtime(state_packet, 2))
    remote_session = self.core.session.remote_session
    state = self.core.state

    self.assertFalse(self.core.handle_runtime(encoded_ack, 3))
    self.assertTrue(self.core.session.established)
    self.assertEqual(self.core.session.remote_session, remote_session)
    self.assertEqual(self.core.session.rx_sequence.highest, 100)
    self.assertEqual(self.core.state, state)
    self.assertFalse(self.core.handle_runtime(state_packet, 4))
    self.assertEqual(self.core.session.rx_sequence.highest, 100)
    self.assertEqual(self.core.state, state)

  def test_fault_and_unknown_health_suppress_semantic_warnings(self):
    for sequence, health in enumerate((RaveHealth.FAULT, RaveHealth.UNKNOWN)):
      with self.subTest(health=health):
        if not self.core.session.established:
          establish(self.core)
        self.assertTrue(self.core.handle_runtime(rave_packet(self.core, sequence, health=health), sequence + 10))
        self.assertEqual(self.core.state.connection, "connected")
        self.assertEqual(self.core.state.health, health.name.lower())
        self.assertEqual((self.core.state.left_lane, self.core.state.right_lane), ("unknown", "unknown"))
        self.assertEqual((self.core.state.left_threat, self.core.state.right_threat), ("none", "none"))

  def test_vehicle_mapping_and_no_steering_torque(self):
    establish(self.core)
    car_state = SimpleNamespace(vEgo=10.0, aEgo=-1.0, steeringAngleDeg=2.0, steeringRateDeg=3.0,
      steeringPressed=True, leftBlinker=True, rightBlinker=False, brakePressed=False,
      gearShifter="drive", standstill=False, leftBlindspot=True, rightBlindspot=False,
      canValid=True, canTimeout=False, steeringTorque=9999.0)
    encoded = self.core.vehicle_packet(car_state, 10)
    packet = decode_packet(encoded, self.core.comma_to_rave)
    car_state.steeringTorque = -999999.0
    second = decode_packet(self.core.vehicle_packet(car_state, 11), self.core.comma_to_rave)
    state = unpack_vehicle_state(packet.payload)
    self.assertEqual((state.v_ego, state.a_ego, state.gear), (10.0, -1.0, 4))
    self.assertTrue(state.flags & VehicleFlags.LEFT_BLINKER)
    self.assertTrue(state.flags & VehicleFlags.LEFT_BLINDSPOT)
    self.assertEqual(packet.payload, second.payload)
    self.assertEqual(len(packet.payload), 20)

  def test_no_vehicle_before_session_disable_and_forget_clear(self):
    car_state = SimpleNamespace()
    self.assertIsNone(self.core.vehicle_packet(car_state, 0))
    establish(self.core)
    self.core.handle_runtime(rave_packet(self.core, 0), 1)
    self.core.configure(False)
    self.assertEqual(self.core.state.connection, "disabled")
    self.assertEqual(self.core.state.left_threat, "none")
    self.core.configure(True, "pi-id", "RAVE-Pi5", MASTER)
    self.core.forget()
    self.assertFalse(self.core.paired)
    self.assertEqual(self.core.state.connection, "notPaired")

  def test_peer_restart_resets_loss_and_counts_once(self):
    establish(self.core, b"p" * 16)
    self.core.handle_runtime(rave_packet(self.core, 3628, pi_session=b"p" * 16), 1)
    self.core.invalidate_runtime()
    establish(self.core, b"q" * 16)
    self.assertEqual(self.core.peer_restarts, 1)
    self.assertTrue(self.core.handle_runtime(rave_packet(self.core, 0, pi_session=b"q" * 16), 2))
    self.assertEqual(self.core.session.rx_sequence.lost, 0)

  def test_receive_drain_is_bounded_and_latest_wins(self):
    establish(self.core)
    packets = [rave_packet(self.core, i, ThreatLevel.WATCH if i < 20 else ThreatLevel.WARNING) for i in range(32)]

    class FakeSocket:
      def __init__(self, values):
        self.values = list(values)
        self.calls = 0

      def recvfrom(self, _size):
        self.calls += 1
        if not self.values:
          raise BlockingIOError
        return self.values.pop(0), ("10.77.0.1", 47771)

    daemon = object.__new__(RaveLinkDaemon)
    daemon.core = self.core
    fake = FakeSocket(packets)
    daemon._drain(fake, False, 10)
    self.assertEqual(fake.calls, MAX_RECEIVE_DRAIN)
    self.assertEqual(self.core.session.rx_sequence.highest, MAX_RECEIVE_DRAIN - 1)
    self.assertEqual(self.core.state.left_threat, "watch")

  def test_comma_restart_rejects_old_bound_state(self):
    pi = PiEndpoint("pi-id", "RAVE-Pi5", MASTER, b"p" * 16)
    old_core = self.core
    challenge = old_core.make_challenge(1)
    ack = pi.handle_runtime(challenge, 1)
    self.assertTrue(old_core.handle_runtime(ack, 1))
    old_packet = pi.rave_state_packet(2)
    self.assertTrue(old_core.handle_runtime(old_packet, 2))

    new_core = RaveLinkCore(now_ns=3)
    new_core.configure(True, "pi-id", "RAVE-Pi5", MASTER)
    self.assertFalse(new_core.handle_runtime(old_packet, 3))
    ack = pi.handle_runtime(new_core.make_challenge(4), 4)
    self.assertTrue(new_core.handle_runtime(ack, 4))
    self.assertTrue(new_core.handle_runtime(pi.rave_state_packet(5), 5))

  def test_both_restart_establishes_new_relationship(self):
    pi = PiEndpoint("pi-id", "RAVE-Pi5", MASTER, b"p" * 16)
    pi.restart()
    new_core = RaveLinkCore(now_ns=1)
    new_core.configure(True, "pi-id", "RAVE-Pi5", MASTER)
    ack = pi.handle_runtime(new_core.make_challenge(2), 2)
    self.assertTrue(new_core.handle_runtime(ack, 2))
    self.assertEqual(new_core.state.connection, "waiting")
    self.assertTrue(new_core.handle_runtime(pi.rave_state_packet(3), 3))
    self.assertEqual(new_core.state.connection, "connected")

  def test_repair_excludes_old_runtime_until_cancelled(self):
    establish(self.core)
    self.assertTrue(self.core.handle_runtime(rave_packet(self.core, 0), 2))
    old_ack = Packet(MessageType.SESSION_ACK, b"p" * 16, self.core.session.local_session, 1, 3,
                     SESSION_ACK_STRUCT.pack(self.core.session.challenge))
    self.assertTrue(self.core.start_pairing(4))
    self.assertEqual(self.core.state.connection, "pairing")
    self.assertIsNone(self.core.make_challenge(5))
    self.assertFalse(self.core.handle_runtime(encode_packet(old_ack, self.core.rave_to_comma), 5))
    self.assertFalse(self.core.handle_runtime(rave_packet(self.core, 1), 5))
    self.assertIsNone(self.core.vehicle_packet(SimpleNamespace(), 5))
    self.assertEqual(self.core.state.connection, "pairing")
    self.core.cancel_pairing()
    self.assertIsNotNone(self.core.make_challenge(6))


class FakeParams:
  def __init__(self, values=None):
    self.values = dict(values or {})

  def get_bool(self, key):
    return bool(self.values.get(key, False))

  def remove(self, key):
    self.values.pop(key, None)

  def put(self, key, value):
    self.values[key] = value


class FakeBoundSocket:
  def __init__(self):
    self.closed = False

  def close(self):
    self.closed = True


class TestDaemonLifecycle(unittest.TestCase):
  def make_daemon(self, enabled=True, paired=True):
    daemon = object.__new__(RaveLinkDaemon)
    daemon.core = RaveLinkCore(now_ns=0)
    daemon.core.configure(enabled, "pi-id" if paired else "", "RAVE-Pi5" if paired else "", MASTER if paired else None)
    daemon.params = FakeParams({"IsOffroad": True, "IsOnroad": False})
    daemon.params_memory = FakeParams()
    daemon.runtime_socket = daemon.pairing_socket = None
    daemon.next_network_retry_ns = 0
    daemon.next_vehicle_ns = 0
    daemon.cloudlog = SimpleNamespace(warning=lambda *_args: None)
    return daemon

  def test_socket_factory_binds_only_dedicated_address(self):
    calls = []

    class RecordingSocket:
      def setsockopt(self, *_args): pass
      def setblocking(self, *_args): pass
      def bind(self, address): calls.append(address)

    original = socket.socket
    socket.socket = lambda *_args: RecordingSocket()
    try:
      RaveLinkDaemon._make_socket(47771)
    finally:
      socket.socket = original
    self.assertEqual(calls, [("10.77.0.2", 47771)])
    self.assertNotIn(("", 47771), calls)
    self.assertNotIn(("0.0.0.0", 47771), calls)

  def test_address_unavailable_remains_alive_and_retries_bounded(self):
    daemon = self.make_daemon()
    calls = []

    def unavailable(port):
      calls.append(port)
      raise OSError("address unavailable")

    daemon._socket_factory = unavailable
    self.assertFalse(daemon._ensure_network(100))
    self.assertEqual(daemon.core.state.connection, "error")
    self.assertEqual(daemon.core.state.reason, "networkUnavailable")
    self.assertEqual(calls, [47771])
    self.assertFalse(daemon._ensure_network(500_000_000))
    self.assertEqual(calls, [47771])
    self.assertFalse(daemon._ensure_network(1_000_000_100))
    self.assertEqual(calls, [47771, 47771])

  def test_address_loss_after_bind_does_not_escape(self):
    daemon = self.make_daemon()

    class FailedSocket(FakeBoundSocket):
      def sendto(self, *_args):
        raise OSError("interface disappeared")

    daemon.runtime_socket = FailedSocket()
    daemon.pairing_socket = FakeBoundSocket()
    self.assertFalse(daemon._sendto(daemon.runtime_socket, b"packet", ("10.77.0.1", 47771), 123))
    self.assertIsNone(daemon.runtime_socket)
    self.assertIsNone(daemon.pairing_socket)
    self.assertEqual(daemon.next_network_retry_ns, 1_000_000_123)
    self.assertEqual(daemon.core.state.reason, "networkUnavailable")

  def test_disabled_network_is_inert(self):
    daemon = self.make_daemon(enabled=False, paired=False)
    calls = []
    daemon._socket_factory = lambda port: calls.append(port)
    self.assertFalse(daemon._ensure_network(0))
    self.assertEqual(calls, [])

  def test_no_socket_waits_when_disabled_or_network_unavailable(self):
    for enabled, unavailable in ((False, False), (True, True)):
      with self.subTest(enabled=enabled):
        daemon = self.make_daemon(enabled=enabled, paired=enabled)
        if unavailable:
          daemon._socket_factory = lambda _port: (_ for _ in ()).throw(OSError("unavailable"))
          self.assertFalse(daemon._ensure_network(0))
        with patch("openpilot.starpilot.system.rave_linkd.rave_linkd.time.sleep") as sleep:
          self.assertEqual(daemon._wait_for_io([], 0.1, 1), [])
          sleep.assert_called_once_with(0.1)

  def test_select_oserror_enters_bounded_network_recovery(self):
    daemon = self.make_daemon()
    daemon.runtime_socket = FakeBoundSocket()
    daemon.pairing_socket = FakeBoundSocket()
    with patch("openpilot.starpilot.system.rave_linkd.rave_linkd.select.select", side_effect=OSError("bad fd")):
      self.assertEqual(daemon._wait_for_io([daemon.runtime_socket], 0.02, 44), [])
    self.assertIsNone(daemon.runtime_socket)
    self.assertIsNone(daemon.pairing_socket)
    self.assertEqual(daemon.next_network_retry_ns, 1_000_000_044)

  def test_absolute_vehicle_deadline_has_no_drift_or_catchup(self):
    deadline = 0
    sends = 0
    for now_ns in range(0, 1_000_000_000, 1_000_000):
      due, deadline = RaveLinkDaemon._advance_deadline(now_ns, deadline, 20_000_000)
      sends += due
    self.assertEqual(sends, 50)
    self.assertEqual(deadline, 1_000_000_000)

    deadline = 0
    due_times = []
    for now_ns in (0, 7_000_000, 23_000_000, 41_000_000, 67_000_000, 82_000_000, 101_000_000):
      due, deadline = RaveLinkDaemon._advance_deadline(now_ns, deadline, 20_000_000)
      if due:
        due_times.append(now_ns)
      self.assertEqual(deadline % 20_000_000, 0)
    self.assertEqual(len(due_times), 6)
    due, deadline = RaveLinkDaemon._advance_deadline(1_000_000_000, deadline, 20_000_000)
    self.assertTrue(due)
    self.assertEqual(deadline, 1_020_000_000)

  def test_vehicle_state_is_refreshed_after_wait_and_sent_once(self):
    daemon = self.make_daemon()
    establish(daemon.core)
    newest = SimpleNamespace(vEgo=42.0, aEgo=0.0, steeringAngleDeg=0.0, steeringRateDeg=0.0,
      steeringPressed=False, leftBlinker=False, rightBlinker=False, brakePressed=False,
      gearShifter="drive", standstill=False, leftBlindspot=False, rightBlindspot=False,
      canValid=True, canTimeout=False)

    class FakeSubMaster:
      valid = {"carState": True}
      def __init__(self): self.updates = 0
      def update(self, _timeout): self.updates += 1
      def __getitem__(self, _key): return newest

    class SendSocket(FakeBoundSocket):
      def __init__(self): super().__init__(); self.sent = []
      def sendto(self, data, destination): self.sent.append((data, destination))

    daemon.sm = FakeSubMaster()
    daemon.runtime_socket = SendSocket()
    self.assertTrue(daemon._send_vehicle_if_due(100, True))
    self.assertEqual(daemon.sm.updates, 1)
    self.assertEqual(len(daemon.runtime_socket.sent), 1)
    packet = decode_packet(daemon.runtime_socket.sent[0][0], daemon.core.comma_to_rave)
    self.assertEqual(unpack_vehicle_state(packet.payload).v_ego, 42.0)
    self.assertFalse(daemon._send_vehicle_if_due(101, True))
    self.assertEqual(len(daemon.runtime_socket.sent), 1)

  def test_startup_clears_only_rave_commands(self):
    daemon = self.make_daemon()
    daemon.params_memory = FakeParams({key: True for key in RaveLinkDaemon.TRANSIENT_COMMANDS} | {"UnrelatedCommand": True})
    daemon._clear_transient_commands()
    self.assertEqual(daemon.params_memory.values, {"UnrelatedCommand": True})

  def test_pairing_cancelled_if_offroad_state_changes_and_confirm_is_ignored(self):
    daemon = self.make_daemon(paired=False)
    daemon.params_memory.values["RavePairRequest"] = True
    daemon._consume_commands(100)
    self.assertTrue(daemon.core.pairing.active)
    daemon.core.pairing.candidate = SimpleNamespace(device_name="candidate")
    daemon.params.values = {"IsOffroad": False, "IsOnroad": True}
    daemon.params_memory.values["RavePairConfirm"] = True
    daemon._consume_commands(200)
    self.assertFalse(daemon.core.pairing.active)
    self.assertNotIn("RavePairConfirm", daemon.params_memory.values)
    self.assertNotIn("RavePairingKey", daemon.params.values)

  def test_publish_uses_daemon_messaging_and_exposes_pairing_candidate(self):
    daemon = self.make_daemon(paired=False)
    daemon.core.start_pairing(0)
    daemon.core.pairing.candidate = SimpleNamespace(device_name="Candidate-Pi")
    daemon.vehicle_tx_hz = daemon.rave_rx_hz = 0.0
    daemon.last_published_state = None

    class FakeState(SimpleNamespace):
      pass
    message = SimpleNamespace(raveState=FakeState())
    daemon.messaging = SimpleNamespace(new_message=lambda service, valid: message)
    sent = []
    daemon.pm = SimpleNamespace(send=lambda service, msg: sent.append((service, msg)))
    daemon._publish(123)
    self.assertEqual(sent, [("raveState", message)])
    self.assertEqual(message.raveState.connectionState, "pairing")
    self.assertEqual(message.raveState.peerName, "Candidate-Pi")
    daemon.core.cancel_pairing()
    daemon.core.peer_name = "Persisted-Pi"
    daemon._publish(124)
    self.assertEqual(message.raveState.peerName, "Persisted-Pi")

  def test_receive_oserror_enters_bounded_network_recovery(self):
    daemon = self.make_daemon()
    class FailedReceiveSocket(FakeBoundSocket):
      def recvfrom(self, _size): raise OSError("interface disappeared")
    daemon.runtime_socket = FailedReceiveSocket()
    daemon.pairing_socket = FakeBoundSocket()
    daemon._drain(daemon.runtime_socket, False, 321)
    self.assertIsNone(daemon.runtime_socket)
    self.assertIsNone(daemon.pairing_socket)
    self.assertEqual(daemon.next_network_retry_ns, 1_000_000_321)
    self.assertEqual(daemon.core.state.reason, "networkUnavailable")

  def test_pair_request_requires_unambiguous_offroad_state(self):
    cases = (
      (True, False, True, "offroad"),
      (False, True, False, "onroad"),
      (False, False, False, "ambiguous"),
      (True, True, False, "contradictory"),
      (None, None, False, "missing"),
    )
    for is_offroad, is_onroad, allowed, label in cases:
      with self.subTest(label=label):
        daemon = self.make_daemon(paired=False)
        daemon.params.values = {}
        if is_offroad is not None:
          daemon.params.values["IsOffroad"] = is_offroad
        if is_onroad is not None:
          daemon.params.values["IsOnroad"] = is_onroad
        daemon.params_memory.values["RavePairRequest"] = True
        daemon.cloudlog = SimpleNamespace(warning=lambda *_args: None)
        daemon._consume_commands(100)
        self.assertEqual(daemon.core.pairing.active, allowed)
        self.assertNotIn("RavePairRequest", daemon.params_memory.values)

  def test_onroad_paired_runtime_reconnect_remains_allowed(self):
    paired = self.make_daemon(paired=True)
    paired.params.values = {"IsOffroad": False, "IsOnroad": True}
    self.assertIsNotNone(paired.core.make_challenge(100))


if __name__ == "__main__":
  unittest.main()
