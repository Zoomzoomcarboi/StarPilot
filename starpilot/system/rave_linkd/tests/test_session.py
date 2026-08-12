import unittest

from openpilot.starpilot.system.rave_linkd.constants import MessageType
from openpilot.starpilot.system.rave_linkd.protocol import Packet, SESSION_ACK_STRUCT
from openpilot.starpilot.system.rave_linkd.session import CommaSession, SequenceError, SequenceTracker


class TestSession(unittest.TestCase):
  def test_challenge_ack_and_old_ack(self):
    session = CommaSession(b"c" * 16)
    challenge = session.challenge
    ack = Packet(MessageType.SESSION_ACK, b"p" * 16, b"c" * 16, 0, 0, SESSION_ACK_STRUCT.pack(challenge))
    self.assertTrue(session.accept_ack(ack))
    self.assertTrue(session.established)
    session.rx_sequence.accept(100)
    original_tracker = session.rx_sequence
    self.assertFalse(session.accept_ack(ack))
    self.assertTrue(session.established)
    self.assertEqual(session.remote_session, b"p" * 16)
    self.assertIs(session.rx_sequence, original_tracker)
    self.assertEqual(session.rx_sequence.highest, 100)
    old = Packet(MessageType.SESSION_ACK, b"p" * 16, b"c" * 16, 0, 0, SESSION_ACK_STRUCT.pack(b"x" * 16))
    self.assertFalse(session.accept_ack(old))

  def test_wrong_peer_or_zero_sender(self):
    session = CommaSession(b"c" * 16)
    for sender, peer in ((b"p" * 16, b"x" * 16), (bytes(16), b"c" * 16)):
      ack = Packet(MessageType.SESSION_ACK, sender, peer, 0, 0, SESSION_ACK_STRUCT.pack(session.challenge))
      self.assertFalse(session.accept_ack(ack))

  def test_runtime_session_binding(self):
    session = CommaSession(b"c" * 16)
    session.accept_ack(Packet(MessageType.SESSION_ACK, b"p" * 16, b"c" * 16, 0, 0,
                              SESSION_ACK_STRUCT.pack(session.challenge)))
    good = Packet(MessageType.RAVE_STATE, b"p" * 16, b"c" * 16, 10, 0, b"")
    self.assertEqual(session.accept_runtime(good), 0)
    with self.assertRaises(SequenceError):
      session.accept_runtime(Packet(MessageType.RAVE_STATE, b"q" * 16, b"c" * 16, 11, 0, b""))

  def test_sequence_duplicate_backward_gap_and_wrap(self):
    tracker = SequenceTracker()
    self.assertEqual(tracker.accept(3628), 0)
    self.assertEqual(tracker.accept(3631), 2)
    with self.assertRaises(SequenceError):
      tracker.accept(3631)
    with self.assertRaises(SequenceError):
      tracker.accept(0)
    wrap = SequenceTracker(0xFFFFFFFE)
    self.assertEqual(wrap.accept(0xFFFFFFFF), 0)
    self.assertEqual(wrap.accept(0), 0)
    self.assertEqual(wrap.accept(2), 1)

  def test_new_session_resets_sequence(self):
    old = CommaSession(b"c" * 16)
    old.accept_ack(Packet(MessageType.SESSION_ACK, b"1" * 16, b"c" * 16, 0, 0,
                          SESSION_ACK_STRUCT.pack(old.challenge)))
    old.accept_runtime(Packet(MessageType.RAVE_STATE, b"1" * 16, b"c" * 16, 3628, 0, b""))
    old.new_attempt()
    old.accept_ack(Packet(MessageType.SESSION_ACK, b"2" * 16, b"c" * 16, 0, 0,
                          SESSION_ACK_STRUCT.pack(old.challenge)))
    self.assertEqual(old.accept_runtime(Packet(MessageType.RAVE_STATE, b"2" * 16, b"c" * 16, 0, 0, b"")), 0)
    self.assertEqual(old.rx_sequence.lost, 0)


if __name__ == "__main__":
  unittest.main()
