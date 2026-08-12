import unittest
from pathlib import Path
import stat
import tempfile

from openpilot.starpilot.system.rave_linkd.pairing import (
  CommaPairing, PairOffer, key_confirm_payload, pack_offer, unpack_key_install, validate_complete,
)
from openpilot.starpilot.system.rave_linkd.protocol import ProtocolError, derive_directional_keys
from openpilot.starpilot.system.rave_linkd.constants import MessageType, ZERO_SESSION
from openpilot.starpilot.system.rave_linkd.protocol import Packet, encode_packet
from openpilot.starpilot.system.rave_linkd.session import CommaSession
from openpilot.tools.rave.rave_sim import PiEndpoint, load_key, process_endpoint_packet


class TestPairing(unittest.TestCase):
  def setUp(self):
    self.comma = CommaPairing()
    self.comma.start(100, 1000)
    self.offer = PairOffer(self.comma.transaction_id, b"n" * 16, "pi-id", "RAVE-Pi5")

  def test_success_and_idempotent_retries(self):
    self.assertEqual(self.comma.accept_offer(pack_offer(self.offer)), self.offer)
    self.assertEqual(self.comma.accept_offer(pack_offer(self.offer)), self.offer)
    install1 = self.comma.confirm_payload()
    install2 = self.comma.confirm_payload()
    self.assertEqual(install1, install2)
    transaction, nonce, device_id, key = unpack_key_install(install1)
    self.assertEqual((transaction, nonce, device_id), (self.offer.transaction_id, b"n" * 16, "pi-id"))
    result = self.comma.accept_key_confirm(key_confirm_payload(self.offer, key))
    self.assertEqual(result.master_key, key)
    validate_complete(self.comma.complete_payload(), self.offer, key)

  def test_timeout_cancel_and_outside_window(self):
    self.assertFalse(self.comma.expire(1099))
    self.assertTrue(self.comma.expire(1100))
    with self.assertRaises(ProtocolError):
      self.comma.accept_offer(pack_offer(self.offer))
    self.comma.start(0, 10)
    self.comma.cancel()
    self.assertFalse(self.comma.active)

  def test_wrong_transaction_nonce_and_confirmation(self):
    wrong_tx = PairOffer(b"x" * 16, b"n" * 16, "pi-id", "RAVE-Pi5")
    with self.assertRaises(ProtocolError):
      self.comma.accept_offer(pack_offer(wrong_tx))
    self.comma.accept_offer(pack_offer(self.offer))
    key = unpack_key_install(self.comma.confirm_payload())[3]
    wrong_nonce = PairOffer(self.offer.transaction_id, b"x" * 16, "pi-id", "RAVE-Pi5")
    with self.assertRaises(ProtocolError):
      self.comma.accept_key_confirm(key_confirm_payload(wrong_nonce, key))

  def test_lost_complete_recovers_with_authenticated_runtime_challenge(self):
    pi = PiEndpoint("pi-id", "RAVE-Pi5")
    probe = Packet(MessageType.PAIR_PROBE, ZERO_SESSION, ZERO_SESSION, 0, 0, self.comma.probe_payload())
    offer_packet = pi.handle_pairing(encode_packet(probe, None), 1)
    self.assertIsNotNone(offer_packet)
    from openpilot.starpilot.system.rave_linkd.protocol import decode_packet
    offer = decode_packet(offer_packet, None, allow_unauthenticated=True)
    self.comma.accept_offer(offer.payload)
    install = Packet(MessageType.PAIR_KEY_INSTALL, ZERO_SESSION, ZERO_SESSION, 0, 2, self.comma.confirm_payload())
    confirm_packet = pi.handle_pairing(encode_packet(install, None), 2)
    self.assertIsNotNone(confirm_packet)
    key = self.comma.master_key
    self.assertIsNotNone(key)
    self.comma.accept_key_confirm(decode_packet(confirm_packet, key).payload)

    # Deliberately drop PAIR_COMPLETE. A valid challenge proves comma persisted the key.
    session = CommaSession(b"c" * 16)
    c2r, _ = derive_directional_keys(key)
    ack = pi.handle_runtime(encode_packet(session.challenge_packet(3), c2r), 3)
    self.assertIsNotNone(ack)
    self.assertEqual(pi.master_key, key)

  def _install_pending_key(self, pi: PiEndpoint, key_file: Path):
    probe = Packet(MessageType.PAIR_PROBE, ZERO_SESSION, ZERO_SESSION, 0, 0, self.comma.probe_payload())
    offer_packet = process_endpoint_packet(pi, encode_packet(probe, None), 1, True, key_file)
    from openpilot.starpilot.system.rave_linkd.protocol import decode_packet
    self.comma.accept_offer(decode_packet(offer_packet, None, allow_unauthenticated=True).payload)
    install = Packet(MessageType.PAIR_KEY_INSTALL, ZERO_SESSION, ZERO_SESSION, 0, 2, self.comma.confirm_payload())
    confirm_packet = process_endpoint_packet(pi, encode_packet(install, None), 2, True, key_file)
    key = self.comma.master_key
    self.comma.accept_key_confirm(decode_packet(confirm_packet, key).payload)
    return key

  def test_simulator_normal_completion_persists_and_reloads_key(self):
    with tempfile.TemporaryDirectory() as directory:
      key_file = Path(directory) / "pairing.json"
      pi = PiEndpoint("pi-id", "RAVE-Pi5")
      key = self._install_pending_key(pi, key_file)
      self.assertFalse(key_file.exists())
      complete = Packet(MessageType.PAIR_COMPLETE, ZERO_SESSION, ZERO_SESSION, 0, 3,
                        self.comma.complete_payload())
      self.assertIsNone(process_endpoint_packet(pi, encode_packet(complete, key), 3, True, key_file))
      self.assertEqual(stat.S_IMODE(key_file.stat().st_mode), 0o600)
      device_id, device_name, reloaded = load_key(key_file)
      restarted = PiEndpoint(device_id, device_name, reloaded)
      self.assertEqual((restarted.device_id, restarted.device_name, restarted.master_key),
                       ("pi-id", "RAVE-Pi5", key))

  def test_simulator_lost_completion_challenge_persists_key(self):
    with tempfile.TemporaryDirectory() as directory:
      key_file = Path(directory) / "pairing.json"
      pi = PiEndpoint("pi-id", "RAVE-Pi5")
      key = self._install_pending_key(pi, key_file)
      session = CommaSession(b"c" * 16)
      c2r, _ = derive_directional_keys(key)
      ack = process_endpoint_packet(pi, encode_packet(session.challenge_packet(3), c2r), 3, False, key_file)
      self.assertIsNotNone(ack)
      self.assertEqual(load_key(key_file), ("pi-id", "RAVE-Pi5", key))


if __name__ == "__main__":
  unittest.main()
