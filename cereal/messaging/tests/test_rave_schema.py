from pathlib import Path

from cereal import custom, log, messaging
from cereal.services import SERVICE_LIST


def test_rave_service_registered():
  assert SERVICE_LIST["raveState"].frequency == 10.0


def test_rave_state_round_trip_and_defaults():
  msg = messaging.new_message("raveState", valid=True)
  msg.raveState.connectionState = "connected"
  msg.raveState.health = "ok"
  msg.raveState.leftLane = "occupied"
  msg.raveState.leftThreat = "warning"
  with log.Event.from_bytes(msg.to_bytes()) as restored:
    assert restored.which() == "raveState"
    assert restored.raveState.connectionState == "connected"
    assert restored.raveState.leftThreat == "warning"
    assert restored.raveState.rightThreat == "none"


def test_rave_state_publish_subscribe_round_trip():
  pm = messaging.PubMaster(["raveState"])
  sm = messaging.SubMaster(["raveState"])
  msg = messaging.new_message("raveState", valid=True)
  msg.raveState.connectionState = "connected"
  msg.raveState.leftLane = "occupied"
  msg.raveState.leftThreat = "warning"
  pm.send("raveState", msg)
  sm.update(1000)
  assert sm.updated["raveState"]
  assert sm.valid["raveState"]
  assert sm["raveState"].connectionState == "connected"
  assert sm["raveState"].leftLane == "occupied"
  assert sm["raveState"].leftThreat == "warning"


def test_reserved_identity_and_event_ordinal_are_preserved():
  assert custom.RaveState.schema.node.id == 0x9ccdc8676701b412
  cereal_root = Path(__file__).resolve().parents[2]
  assert "raveState @138 :Custom.RaveState;" in (cereal_root / "log.capnp").read_text()
