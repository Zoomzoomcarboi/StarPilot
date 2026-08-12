from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import struct

from openpilot.starpilot.system.rave_linkd.constants import (
  HMAC_SIZE, MAGIC, MASTER_KEY_SIZE, MAX_DATAGRAM_SIZE, MessageType, PacketFlags,
  PROTOCOL_VERSION, SESSION_ID_SIZE, ZERO_SESSION,
)

HEADER_STRUCT = struct.Struct("!4sBBH16s16sIQHH")
HEADER_SIZE = HEADER_STRUCT.size
MIN_PACKET_SIZE = HEADER_SIZE + HMAC_SIZE
CHALLENGE_STRUCT = struct.Struct("!16s")
SESSION_ACK_STRUCT = struct.Struct("!16s")
VEHICLE_STATE_STRUCT = struct.Struct("!ffffHBx")
RAVE_STATE_STRUCT = struct.Struct("!BBBBB3x")


class ProtocolError(ValueError):
  pass


class AuthenticationError(ProtocolError):
  pass


@dataclass(frozen=True)
class Packet:
  message_type: MessageType
  sender_session: bytes
  peer_session: bytes
  sequence: int
  sender_monotonic_ns: int
  payload: bytes
  flags: int = 0


@dataclass(frozen=True)
class VehicleState:
  v_ego: float
  a_ego: float
  steering_angle_deg: float
  steering_rate_deg: float
  flags: int
  gear: int


@dataclass(frozen=True)
class RavePayload:
  health: int
  left_lane: int
  right_lane: int
  left_threat: int
  right_threat: int


def derive_directional_keys(master_key: bytes) -> tuple[bytes, bytes]:
  if len(master_key) != MASTER_KEY_SIZE:
    raise ValueError("RAVE master key must be exactly 32 bytes")
  return (
    hmac.digest(master_key, b"RAVE v1 comma->pi", "sha256"),
    hmac.digest(master_key, b"RAVE v1 pi->comma", "sha256"),
  )


def encode_packet(packet: Packet, key: bytes | None) -> bytes:
  if len(packet.sender_session) != SESSION_ID_SIZE or len(packet.peer_session) != SESSION_ID_SIZE:
    raise ValueError("session IDs must be exactly 16 bytes")
  if len(packet.payload) > MAX_DATAGRAM_SIZE - MIN_PACKET_SIZE:
    raise ValueError("payload exceeds RAVE datagram bound")
  if packet.flags != PacketFlags.NONE:
    raise ValueError("unsupported packet flags")
  header = HEADER_STRUCT.pack(
    MAGIC, PROTOCOL_VERSION, int(packet.message_type), packet.flags,
    packet.sender_session, packet.peer_session, packet.sequence & 0xFFFFFFFF,
    packet.sender_monotonic_ns, len(packet.payload), 0,
  )
  authenticated = header + packet.payload
  tag = bytes(HMAC_SIZE) if key is None else hmac.digest(key, authenticated, "sha256")
  return authenticated + tag


def decode_packet(data: bytes, key: bytes | None, *, allow_unauthenticated: bool = False) -> Packet:
  if not MIN_PACKET_SIZE <= len(data) <= MAX_DATAGRAM_SIZE:
    raise ProtocolError("packet length outside bounds")
  magic, version, raw_type, flags, sender, peer, sequence, mono_ns, payload_len, reserved = HEADER_STRUCT.unpack_from(data)
  if magic != MAGIC:
    raise ProtocolError("bad magic")
  if version != PROTOCOL_VERSION:
    raise ProtocolError("unsupported protocol version")
  try:
    message_type = MessageType(raw_type)
  except ValueError as e:
    raise ProtocolError("unknown message type") from e
  if flags != PacketFlags.NONE:
    raise ProtocolError("unsupported flags")
  if reserved != 0:
    raise ProtocolError("reserved field must be zero")
  if HEADER_SIZE + payload_len + HMAC_SIZE != len(data):
    raise ProtocolError("declared payload length mismatch")

  authenticated, received_tag = data[:-HMAC_SIZE], data[-HMAC_SIZE:]
  if key is None:
    if not allow_unauthenticated or received_tag != bytes(HMAC_SIZE):
      raise AuthenticationError("authentication key unavailable")
  elif not hmac.compare_digest(received_tag, hmac.digest(key, authenticated, "sha256")):
    raise AuthenticationError("invalid authentication tag")

  payload = data[HEADER_SIZE:-HMAC_SIZE]
  _validate_payload_size(message_type, payload)
  return Packet(message_type, sender, peer, sequence, mono_ns, payload, flags)


def _validate_payload_size(message_type: MessageType, payload: bytes) -> None:
  exact_sizes = {
    MessageType.SESSION_CHALLENGE: CHALLENGE_STRUCT.size,
    MessageType.SESSION_ACK: SESSION_ACK_STRUCT.size,
    MessageType.VEHICLE_STATE: VEHICLE_STATE_STRUCT.size,
    MessageType.RAVE_STATE: RAVE_STATE_STRUCT.size,
  }
  expected = exact_sizes.get(message_type)
  if expected is not None and len(payload) != expected:
    raise ProtocolError(f"invalid {message_type.name} payload size")


def pack_vehicle_state(state: VehicleState) -> bytes:
  return VEHICLE_STATE_STRUCT.pack(state.v_ego, state.a_ego, state.steering_angle_deg,
                                   state.steering_rate_deg, state.flags, state.gear)


def unpack_vehicle_state(payload: bytes) -> VehicleState:
  _validate_payload_size(MessageType.VEHICLE_STATE, payload)
  return VehicleState(*VEHICLE_STATE_STRUCT.unpack(payload))


def pack_rave_state(state: RavePayload) -> bytes:
  return RAVE_STATE_STRUCT.pack(state.health, state.left_lane, state.right_lane,
                                state.left_threat, state.right_threat)


def unpack_rave_state(payload: bytes) -> RavePayload:
  _validate_payload_size(MessageType.RAVE_STATE, payload)
  return RavePayload(*RAVE_STATE_STRUCT.unpack(payload)[:5])


def pairing_transcript(transaction_id: bytes, pairing_nonce: bytes, device_id: str,
                       device_name: str, master_key: bytes) -> bytes:
  values = (transaction_id, pairing_nonce, device_id.encode(), device_name.encode(), hashlib.sha256(master_key).digest())
  return b"RAVE v1 pairing\0" + b"".join(struct.pack("!H", len(value)) + value for value in values)


def transcript_digest(*args) -> bytes:
  return hashlib.sha256(pairing_transcript(*args)).digest()


def zero_session_packet(message_type: MessageType, payload: bytes, sequence: int = 0) -> Packet:
  return Packet(message_type, ZERO_SESSION, ZERO_SESSION, sequence, 0, payload)
