import random
import unittest

from openpilot.starpilot.system.rave_linkd.constants import MessageType, ZERO_SESSION
from openpilot.starpilot.system.rave_linkd.protocol import (
  AuthenticationError, HEADER_SIZE, HMAC_SIZE, Packet, ProtocolError, VehicleState,
  decode_packet, derive_directional_keys, encode_packet, pack_vehicle_state, unpack_vehicle_state,
)


class TestProtocol(unittest.TestCase):
  def setUp(self):
    self.master = bytes(range(32))
    self.c2r, self.r2c = derive_directional_keys(self.master)
    self.packet = Packet(MessageType.VEHICLE_STATE, bytes(range(16)), bytes(range(16, 32)),
                         0x01020304, 0x0102030405060708,
                         pack_vehicle_state(VehicleState(1.0, -2.0, 3.5, -4.5, 0x0101, 4)))

  def test_sizes_network_order_and_golden_vector(self):
    encoded = encode_packet(self.packet, self.c2r)
    self.assertEqual(HEADER_SIZE, 56)
    self.assertEqual(HMAC_SIZE, 32)
    self.assertEqual(len(encoded), 108)
    self.assertEqual(encoded.hex(),
      "5241564501030000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
      "010203040102030405060708001400003f800000c000000040600000c090000001010400"
      "3bd15d55478583ed36d324044b7168fa07930ac47eeb791d03450a2e05d78963")
    self.assertEqual(decode_packet(encoded, self.c2r), self.packet)

  def test_full_tag_and_wrong_direction(self):
    encoded = encode_packet(self.packet, self.c2r)
    self.assertEqual(len(encoded[-32:]), 32)
    with self.assertRaises(AuthenticationError):
      decode_packet(encoded, self.r2c)

  def test_vehicle_round_trip(self):
    state = unpack_vehicle_state(self.packet.payload)
    self.assertEqual((state.flags, state.gear), (0x0101, 4))
    self.assertAlmostEqual(state.steering_rate_deg, -4.5)

  def test_structural_rejections(self):
    encoded = bytearray(encode_packet(self.packet, self.c2r))
    mutations = ((0, 0), (4, 2), (5, 255), (6, 1), (54, 1))
    for index, value in mutations:
      bad = encoded.copy()
      bad[index] = value
      with self.assertRaises(ProtocolError, msg=f"index {index}"):
        decode_packet(bytes(bad), self.c2r)
    for bad in (bytes(encoded[:20]), bytes(513), bytes(encoded[:-1])):
      with self.assertRaises(ProtocolError):
        decode_packet(bad, self.c2r)

  def test_unauthenticated_only_when_explicit(self):
    packet = Packet(MessageType.PAIR_PROBE, ZERO_SESSION, ZERO_SESSION, 0, 0, bytes(16))
    encoded = encode_packet(packet, None)
    with self.assertRaises(AuthenticationError):
      decode_packet(encoded, None)
    self.assertEqual(decode_packet(encoded, None, allow_unauthenticated=True), packet)

  def test_random_input_never_escapes_protocol_error(self):
    rng = random.Random(0)
    for _ in range(5000):
      data = rng.randbytes(rng.randrange(0, 600))
      try:
        decode_packet(data, self.c2r)
      except ProtocolError:
        pass


if __name__ == "__main__":
  unittest.main()
