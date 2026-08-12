# RAVE Gate 1 simulator

`rave_sim.py` is the Raspberry Pi/ZBook endpoint for the RAVE v1 protocol. It uses the same binary codec, pairing transcript, HMAC keys, session rules, and vehicle-state decoder as `rave_linkd`.

The comma side must already have `10.77.0.2/24`; the simulator host must have `10.77.0.1/24`. Gate 1 deliberately does not configure either interface automatically.

Run from the repository root:

```bash
python tools/rave/rave_sim.py
```

The simulator responds only to direct unicast pairing probes, stores its pairing key in `rave_pairing.json` with mode `0600`, answers comma-initiated runtime challenges, receives real vehicle state, and emits synthetic left-lane occupancy at 10 Hz. With the real left blinker off it sends `OCCUPIED/WATCH`; with the blinker on it sends `OCCUPIED/WARNING`.

The pairing key file is sensitive. Do not upload it or include it in logs. Delete it only when also using “Forget Paired Device” on the comma.

Interactive commands are `pause`, `resume`, `restart`, `invalid-hmac`, `malformed`, `duplicate`, `out-of-order`, `reset-sequence`, and `old-replay`. They exercise stale recovery, Pi-session replacement, authentication rejection, malformed input, duplicate/out-of-order handling, the same-session reset case, and delayed traffic from the prior Pi session.
