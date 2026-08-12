from __future__ import annotations

from dataclasses import dataclass
import secrets

from openpilot.starpilot.system.rave_linkd.constants import MessageType, ZERO_SESSION
from openpilot.starpilot.system.rave_linkd.protocol import CHALLENGE_STRUCT, Packet, SESSION_ACK_STRUCT

UINT32_MASK = 0xFFFFFFFF
UINT32_HALF = 0x80000000


class SequenceError(ValueError):
  pass


@dataclass
class SequenceTracker:
  highest: int | None = None
  lost: int = 0

  def accept(self, sequence: int) -> int:
    sequence &= UINT32_MASK
    if self.highest is None:
      self.highest = sequence
      return 0
    delta = (sequence - self.highest) & UINT32_MASK
    if delta == 0:
      raise SequenceError("duplicate sequence")
    if delta >= UINT32_HALF:
      raise SequenceError("backward or out-of-order sequence")
    missing = delta - 1
    self.lost += missing
    self.highest = sequence
    return missing


class CommaSession:
  def __init__(self, local_session: bytes | None = None):
    self.local_session = local_session or secrets.token_bytes(16)
    self.remote_session: bytes | None = None
    self.challenge = secrets.token_bytes(16)
    self.established = False
    self.rx_sequence = SequenceTracker()
    self.tx_sequence = 0

  def new_attempt(self) -> None:
    self.challenge = secrets.token_bytes(16)
    self.remote_session = None
    self.established = False
    self.rx_sequence = SequenceTracker()

  def challenge_packet(self, now_ns: int) -> Packet:
    return Packet(MessageType.SESSION_CHALLENGE, self.local_session, ZERO_SESSION, 0,
                  now_ns, CHALLENGE_STRUCT.pack(self.challenge))

  def accept_ack(self, packet: Packet) -> bool:
    if self.established:
      return False
    if packet.message_type != MessageType.SESSION_ACK:
      return False
    if packet.peer_session != self.local_session or packet.sender_session == ZERO_SESSION:
      return False
    if SESSION_ACK_STRUCT.unpack(packet.payload)[0] != self.challenge:
      return False
    self.remote_session = packet.sender_session
    self.established = True
    self.rx_sequence = SequenceTracker()
    return True

  def accept_runtime(self, packet: Packet) -> int:
    if not self.established or self.remote_session is None:
      raise SequenceError("runtime session is not established")
    if packet.sender_session != self.remote_session or packet.peer_session != self.local_session:
      raise SequenceError("runtime session IDs do not match")
    return self.rx_sequence.accept(packet.sequence)

  def next_tx_sequence(self) -> int:
    sequence = self.tx_sequence
    self.tx_sequence = (self.tx_sequence + 1) & UINT32_MASK
    return sequence
