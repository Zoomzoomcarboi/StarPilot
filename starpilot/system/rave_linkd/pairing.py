from __future__ import annotations

from dataclasses import dataclass
import hmac
import secrets
import struct

from openpilot.starpilot.system.rave_linkd.constants import MASTER_KEY_SIZE
from openpilot.starpilot.system.rave_linkd.protocol import ProtocolError, transcript_digest

ID_MAX = 64
NAME_MAX = 64
PAIR_PROBE_STRUCT = struct.Struct("!16s")
PAIR_OFFER_PREFIX = struct.Struct("!16s16sBB")
PAIR_INSTALL_PREFIX = struct.Struct("!16s16sB32s")
PAIR_CONFIRM_STRUCT = struct.Struct("!16s32s")
PAIR_COMPLETE_STRUCT = struct.Struct("!16s32s")
PAIR_CANCEL_STRUCT = struct.Struct("!16s")


@dataclass(frozen=True)
class PairOffer:
  transaction_id: bytes
  pairing_nonce: bytes
  device_id: str
  device_name: str


@dataclass(frozen=True)
class PairingResult:
  device_id: str
  device_name: str
  master_key: bytes


def pack_probe(transaction_id: bytes) -> bytes:
  return PAIR_PROBE_STRUCT.pack(transaction_id)


def unpack_probe(payload: bytes) -> bytes:
  if len(payload) != PAIR_PROBE_STRUCT.size:
    raise ProtocolError("invalid PAIR_PROBE payload")
  return PAIR_PROBE_STRUCT.unpack(payload)[0]


def pack_offer(offer: PairOffer) -> bytes:
  device_id, name = offer.device_id.encode(), offer.device_name.encode()
  if not 1 <= len(device_id) <= ID_MAX or not 1 <= len(name) <= NAME_MAX:
    raise ValueError("pairing identity length outside bounds")
  return PAIR_OFFER_PREFIX.pack(offer.transaction_id, offer.pairing_nonce, len(device_id), len(name)) + device_id + name


def unpack_offer(payload: bytes) -> PairOffer:
  if len(payload) < PAIR_OFFER_PREFIX.size:
    raise ProtocolError("truncated PAIR_OFFER")
  transaction, nonce, id_len, name_len = PAIR_OFFER_PREFIX.unpack_from(payload)
  if not 1 <= id_len <= ID_MAX or not 1 <= name_len <= NAME_MAX or len(payload) != PAIR_OFFER_PREFIX.size + id_len + name_len:
    raise ProtocolError("invalid PAIR_OFFER identity lengths")
  pos = PAIR_OFFER_PREFIX.size
  try:
    return PairOffer(transaction, nonce, payload[pos:pos + id_len].decode(), payload[pos + id_len:].decode())
  except UnicodeDecodeError as e:
    raise ProtocolError("PAIR_OFFER identity is not UTF-8") from e


def pack_key_install(offer: PairOffer, master_key: bytes) -> bytes:
  device_id = offer.device_id.encode()
  if len(master_key) != MASTER_KEY_SIZE or not 1 <= len(device_id) <= ID_MAX:
    raise ValueError("invalid pairing key or identity")
  return PAIR_INSTALL_PREFIX.pack(offer.transaction_id, offer.pairing_nonce, len(device_id), master_key) + device_id


def unpack_key_install(payload: bytes) -> tuple[bytes, bytes, str, bytes]:
  if len(payload) < PAIR_INSTALL_PREFIX.size:
    raise ProtocolError("truncated PAIR_KEY_INSTALL")
  transaction, nonce, id_len, key = PAIR_INSTALL_PREFIX.unpack_from(payload)
  if not 1 <= id_len <= ID_MAX or len(payload) != PAIR_INSTALL_PREFIX.size + id_len:
    raise ProtocolError("invalid PAIR_KEY_INSTALL identity length")
  try:
    device_id = payload[PAIR_INSTALL_PREFIX.size:].decode()
  except UnicodeDecodeError as e:
    raise ProtocolError("PAIR_KEY_INSTALL identity is not UTF-8") from e
  return transaction, nonce, device_id, key


class CommaPairing:
  def __init__(self):
    self.active = False
    self.deadline_ns = 0
    self.transaction_id = b""
    self.candidate: PairOffer | None = None
    self.master_key: bytes | None = None

  def start(self, now_ns: int, duration_ns: int) -> None:
    self.active = True
    self.deadline_ns = now_ns + duration_ns
    self.transaction_id = secrets.token_bytes(16)
    self.candidate = None
    self.master_key = None

  def expire(self, now_ns: int) -> bool:
    if self.active and now_ns >= self.deadline_ns:
      self.cancel()
      return True
    return False

  def cancel(self) -> None:
    self.active = False
    self.deadline_ns = 0
    self.candidate = None
    self.master_key = None

  def probe_payload(self) -> bytes:
    if not self.active:
      raise RuntimeError("pairing is not active")
    return pack_probe(self.transaction_id)

  def accept_offer(self, payload: bytes) -> PairOffer:
    if not self.active:
      raise ProtocolError("PAIR_OFFER outside pairing window")
    offer = unpack_offer(payload)
    if offer.transaction_id != self.transaction_id:
      raise ProtocolError("PAIR_OFFER transaction mismatch")
    if self.candidate is not None and offer != self.candidate:
      raise ProtocolError("pairing candidate changed")
    self.candidate = offer
    return offer

  def confirm_payload(self) -> bytes:
    if not self.active or self.candidate is None:
      raise RuntimeError("no pairing candidate")
    if self.master_key is None:
      self.master_key = secrets.token_bytes(MASTER_KEY_SIZE)
    return pack_key_install(self.candidate, self.master_key)

  def accept_key_confirm(self, payload: bytes, device_name: str | None = None) -> PairingResult:
    if not self.active or self.candidate is None or self.master_key is None:
      raise ProtocolError("PAIR_KEY_CONFIRM outside key installation")
    if len(payload) != PAIR_CONFIRM_STRUCT.size:
      raise ProtocolError("invalid PAIR_KEY_CONFIRM payload")
    transaction, received_digest = PAIR_CONFIRM_STRUCT.unpack(payload)
    expected = transcript_digest(self.candidate.transaction_id, self.candidate.pairing_nonce,
                                 self.candidate.device_id, self.candidate.device_name, self.master_key)
    if transaction != self.transaction_id or not hmac.compare_digest(received_digest, expected):
      raise ProtocolError("PAIR_KEY_CONFIRM transcript mismatch")
    return PairingResult(self.candidate.device_id, device_name or self.candidate.device_name, self.master_key)

  def complete_payload(self) -> bytes:
    if self.candidate is None or self.master_key is None:
      raise RuntimeError("pairing key is not confirmed")
    digest = transcript_digest(self.candidate.transaction_id, self.candidate.pairing_nonce,
                               self.candidate.device_id, self.candidate.device_name, self.master_key)
    return PAIR_COMPLETE_STRUCT.pack(self.transaction_id, digest)


def key_confirm_payload(offer: PairOffer, master_key: bytes) -> bytes:
  digest = transcript_digest(offer.transaction_id, offer.pairing_nonce, offer.device_id, offer.device_name, master_key)
  return PAIR_CONFIRM_STRUCT.pack(offer.transaction_id, digest)


def validate_complete(payload: bytes, offer: PairOffer, master_key: bytes) -> None:
  if len(payload) != PAIR_COMPLETE_STRUCT.size:
    raise ProtocolError("invalid PAIR_COMPLETE payload")
  transaction, received_digest = PAIR_COMPLETE_STRUCT.unpack(payload)
  expected = transcript_digest(offer.transaction_id, offer.pairing_nonce, offer.device_id, offer.device_name, master_key)
  if transaction != offer.transaction_id or not hmac.compare_digest(received_digest, expected):
    raise ProtocolError("PAIR_COMPLETE transcript mismatch")
