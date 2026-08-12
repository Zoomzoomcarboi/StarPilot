#!/usr/bin/env python3
"""RAVE v1 Pi endpoint and synthetic left-occupancy scenario."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import select
import socket
import sys
import tempfile
import time

from openpilot.starpilot.system.rave_linkd.constants import (
  COMMA_ADDRESS, LaneState, MessageType, PAIRING_PORT, RAVE_ADDRESS, RUNTIME_PORT,
  RaveHealth, ThreatLevel, VehicleFlags, ZERO_SESSION,
)
from openpilot.starpilot.system.rave_linkd.pairing import (
  PairOffer, key_confirm_payload, pack_offer, unpack_key_install, unpack_probe, validate_complete,
)
from openpilot.starpilot.system.rave_linkd.protocol import (
  AuthenticationError, CHALLENGE_STRUCT, Packet, ProtocolError, RavePayload, decode_packet, derive_directional_keys,
  encode_packet, pack_rave_state, unpack_vehicle_state,
)
from openpilot.starpilot.system.rave_linkd.session import SequenceError, SequenceTracker


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
    self.rx_sequence = SequenceTracker()
    self.tx_sequence = 0
    self.last_vehicle = None
    self.last_valid_packet: bytes | None = None
    if master_key is not None:
      self._activate_key(master_key)

  def _activate_key(self, key: bytes) -> None:
    self.master_key = key
    self.comma_to_rave, self.rave_to_comma = derive_directional_keys(key)

  def handle_pairing(self, data: bytes, now_ns: int) -> bytes | None:
    try:
      packet = decode_packet(data, None, allow_unauthenticated=True)
    except AuthenticationError:
      if self.pending_key is None:
        return None
      packet = decode_packet(data, self.pending_key)
    if packet.message_type == MessageType.PAIR_PROBE:
      transaction = unpack_probe(packet.payload)
      if self.offer is None or self.offer.transaction_id != transaction:
        self.offer = PairOffer(transaction, secrets.token_bytes(16), self.device_id, self.device_name)
      response = Packet(MessageType.PAIR_OFFER, ZERO_SESSION, ZERO_SESSION, 0, now_ns, pack_offer(self.offer))
      return encode_packet(response, None)
    if packet.message_type == MessageType.PAIR_KEY_INSTALL and self.offer is not None:
      transaction, nonce, device_id, key = unpack_key_install(packet.payload)
      if (transaction, nonce, device_id) != (self.offer.transaction_id, self.offer.pairing_nonce, self.device_id):
        return None
      self.pending_key = key
      payload = key_confirm_payload(self.offer, key)
      return encode_packet(Packet(MessageType.PAIR_KEY_CONFIRM, ZERO_SESSION, ZERO_SESSION, 0, now_ns, payload), key)
    if packet.message_type == MessageType.PAIR_COMPLETE and self.offer is not None and self.pending_key is not None:
      validate_complete(packet.payload, self.offer, self.pending_key)
      self._activate_key(self.pending_key)
      self.pending_key = None
    return None

  def handle_runtime(self, data: bytes, now_ns: int) -> bytes | None:
    if self.master_key is None and self.pending_key is not None:
      pending_c2r, _ = derive_directional_keys(self.pending_key)
      try:
        packet = decode_packet(data, pending_c2r)
      except (AuthenticationError, ProtocolError):
        return None
      if packet.message_type == MessageType.SESSION_CHALLENGE:
        self._activate_key(self.pending_key)
        self.pending_key = None
    if self.comma_to_rave is None or self.rave_to_comma is None:
      return None
    else:
      packet = decode_packet(data, self.comma_to_rave)
    if packet.message_type == MessageType.SESSION_CHALLENGE:
      challenge = CHALLENGE_STRUCT.unpack(packet.payload)[0]
      self.comma_session = packet.sender_session
      self.rx_sequence = SequenceTracker()
      ack = Packet(MessageType.SESSION_ACK, self.pi_session, self.comma_session, 0, now_ns, challenge)
      return encode_packet(ack, self.rave_to_comma)
    if packet.message_type == MessageType.VEHICLE_STATE and self.comma_session is not None:
      if packet.sender_session != self.comma_session or packet.peer_session != self.pi_session:
        raise SequenceError("vehicle packet session mismatch")
      self.rx_sequence.accept(packet.sequence)
      self.last_vehicle = unpack_vehicle_state(packet.payload)
    return None

  def rave_state_packet(self, now_ns: int, left_occupied: bool = True) -> bytes | None:
    if self.comma_session is None or self.rave_to_comma is None:
      return None
    left_intent = bool(self.last_vehicle and self.last_vehicle.flags & VehicleFlags.LEFT_BLINKER)
    payload = RavePayload(
      RaveHealth.OK,
      LaneState.OCCUPIED if left_occupied else LaneState.CLEAR,
      LaneState.CLEAR,
      ThreatLevel.WARNING if left_occupied and left_intent else ThreatLevel.WATCH if left_occupied else ThreatLevel.NONE,
      ThreatLevel.NONE,
    )
    packet = Packet(MessageType.RAVE_STATE, self.pi_session, self.comma_session,
                    self.tx_sequence, now_ns, pack_rave_state(payload))
    self.tx_sequence = (self.tx_sequence + 1) & 0xFFFFFFFF
    self.last_valid_packet = encode_packet(packet, self.rave_to_comma)
    return self.last_valid_packet

  def restart(self) -> None:
    self.pi_session = secrets.token_bytes(16)
    self.comma_session = None
    self.rx_sequence = SequenceTracker()
    self.tx_sequence = 0


def load_key(path: Path) -> tuple[str, str, bytes | None]:
  if not path.exists():
    return "rave-pi5-dev", "RAVE-Pi5", None
  data = json.loads(path.read_text())
  return data["device_id"], data["device_name"], bytes.fromhex(data["master_key"])


def save_key(path: Path, endpoint: PiEndpoint) -> None:
  if endpoint.master_key is None:
    return
  payload = json.dumps({"device_id": endpoint.device_id, "device_name": endpoint.device_name,
                        "master_key": endpoint.master_key.hex()})
  path.parent.mkdir(parents=True, exist_ok=True)
  fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
  try:
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w") as f:
      f.write(payload)
      f.flush()
      os.fsync(f.fileno())
    os.replace(temporary, path)
  finally:
    if os.path.exists(temporary):
      os.unlink(temporary)


def process_endpoint_packet(endpoint: PiEndpoint, data: bytes, now_ns: int, pairing: bool,
                            key_file: Path) -> bytes | None:
  previous_key = endpoint.master_key
  response = endpoint.handle_pairing(data, now_ns) if pairing else endpoint.handle_runtime(data, now_ns)
  if endpoint.master_key is not None and endpoint.master_key != previous_key:
    save_key(key_file, endpoint)
  return response


def main() -> None:
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--bind", default=RAVE_ADDRESS)
  parser.add_argument("--comma", default=COMMA_ADDRESS)
  parser.add_argument("--key-file", type=Path, default=Path("rave_pairing.json"))
  args = parser.parse_args()
  device_id, device_name, key = load_key(args.key_file)
  endpoint = PiEndpoint(device_id, device_name, key)

  runtime = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  pairing = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  for sock, port in ((runtime, RUNTIME_PORT), (pairing, PAIRING_PORT)):
    sock.setblocking(False)
    sock.bind((args.bind, port))

  print("RAVE simulator ready; synthetic LEFT LANE OCCUPIED")
  print("Commands: pause, resume, restart, invalid-hmac, malformed, duplicate, out-of-order, reset-sequence, old-replay")
  last_state_ns = 0
  paused = False
  old_session_packet = None
  monitor_stdin = True
  while True:
    now_ns = time.monotonic_ns()
    inputs = [runtime, pairing] + ([sys.stdin] if monitor_stdin else [])
    readable, _, _ = select.select(inputs, [], [], 0.02)
    for sock in readable:
      if sock is sys.stdin:
        line = sys.stdin.readline()
        if line == "":
          monitor_stdin = False
          continue
        command = line.strip().lower()
        if command == "pause":
          paused = True
        elif command == "resume":
          paused = False
        elif command == "restart":
          old_session_packet = endpoint.last_valid_packet
          endpoint.restart()
        elif command == "invalid-hmac" and endpoint.last_valid_packet:
          bad = bytearray(endpoint.last_valid_packet)
          bad[-1] ^= 1
          runtime.sendto(bytes(bad), (args.comma, RUNTIME_PORT))
        elif command == "malformed":
          runtime.sendto(b"RAVE-malformed", (args.comma, RUNTIME_PORT))
        elif command == "duplicate" and endpoint.last_valid_packet:
          runtime.sendto(endpoint.last_valid_packet, (args.comma, RUNTIME_PORT))
        elif command == "out-of-order":
          endpoint.tx_sequence = max(0, endpoint.tx_sequence - 2)
        elif command == "reset-sequence":
          endpoint.tx_sequence = 0
        elif command == "old-replay" and old_session_packet:
          runtime.sendto(old_session_packet, (args.comma, RUNTIME_PORT))
        continue
      data, source = sock.recvfrom(513)
      if source[0] != args.comma:
        continue
      try:
        response = process_endpoint_packet(endpoint, data, now_ns, sock is pairing, args.key_file)
        if response is not None:
          sock.sendto(response, (args.comma, PAIRING_PORT if sock is pairing else RUNTIME_PORT))
      except (AuthenticationError, ProtocolError, SequenceError, ValueError) as e:
        print(f"Dropped packet: {type(e).__name__}")
    if not paused and now_ns - last_state_ns >= 100_000_000:
      state = endpoint.rave_state_packet(now_ns)
      if state is not None:
        runtime.sendto(state, (args.comma, RUNTIME_PORT))
        if endpoint.last_vehicle and endpoint.last_vehicle.flags & VehicleFlags.LEFT_BLINKER:
          print("LEFT OCCUPIED + LEFT TURN INTENT = LEFT WARNING")
        else:
          print("LEFT OCCUPIED / WATCH — Turn on the left turn signal")
      last_state_ns = now_ns


if __name__ == "__main__":
  main()
