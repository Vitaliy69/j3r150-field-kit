#!/usr/bin/env python3
"""One key's whole life: personalize, authenticate, rotate, revoke.
CardStub stands in for the J3R150 - byte-for-byte the same CMAC the
applet computes. On hardware, CardStub.mac() becomes the pcsc exchange.

Run:  /usr/bin/python3 examples/collar_lifecycle.py
Needs: pip3 install cryptography   (or any python with hazmat.cmac)

The last two lines of the output are the lesson: after revocation the
card still MACs fine. It is healthy, just orphaned - because revocation
is a fact the backend knows and the card never learns.
"""

import os, struct
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms

def cmac_tag(key, data):
    c = cmac.CMAC(algorithms.AES(key)); c.update(data); return c.finalize()

TRANSPORT_KEY = bytes.fromhex("404142434445464748494A4B4C4D4E4F")  # factory dev key - dev only

class CardStub:
    """The key lives 'inside'; only MACs come out. No getter exists."""
    def __init__(self): self.device_key = None
    def personalize(self, wrapped):
        key, tag = wrapped[:16], wrapped[16:]
        assert cmac_tag(TRANSPORT_KEY, key) == tag, "transport MAC failed"
        self.device_key = key
    def mac(self, msg): return cmac_tag(self.device_key, msg)
    def rotate(self, wrapped):
        new_key, tag = wrapped[:16], wrapped[16:]
        assert cmac_tag(self.device_key, new_key) == tag, "rotation MAC failed"
        self.device_key = new_key

class Backend:
    def __init__(self): self.registry = {}          # id -> [key, next_ctr, revoked]
    def enroll(self, dev, key): self.registry[dev] = [key, 1, False]
    def challenge(self, dev):
        rec = self.registry[dev]
        return struct.pack(">I", rec[1]) + os.urandom(8)
    def verify(self, dev, payload, tag):
        rec = self.registry.get(dev)
        if not rec or rec[2]: return "REJECTED: unknown or revoked device"
        if struct.unpack(">I", payload[:4])[0] < rec[1]: return "REJECTED: stale counter"
        if cmac_tag(rec[0], payload) != tag: return "REJECTED: bad MAC"
        rec[1] = struct.unpack(">I", payload[:4])[0] + 1
        return "accepted"
    def rotate(self, dev):
        rec = self.registry[dev]; old = rec[0]; new_key = os.urandom(16)
        rec[0] = new_key
        return new_key + cmac_tag(old, new_key)     # wrapped for the card
    def revoke(self, dev): self.registry[dev][2] = True

card, backend = CardStub(), Backend()
device_key = os.urandom(16)
card.personalize(device_key + cmac_tag(TRANSPORT_KEY, device_key))
backend.enroll("collar-0417", device_key)
print("1) personalized at production, enrolled on backend")

for i in range(2):
    ch = backend.challenge("collar-0417")
    print("2) auth:", backend.verify("collar-0417", ch, card.mac(ch)), f"(round {i+1})")

card.rotate(backend.rotate("collar-0417"))
print("3) rotated: card and backend both hold fresh keys")

ch = backend.challenge("collar-0417")
print("4) auth with fresh key:", backend.verify("collar-0417", ch, card.mac(ch)))

backend.revoke("collar-0417")
offline = struct.pack(">I", 9) + os.urandom(8)   # no challenge is issued anymore
print("5) after revocation:", backend.verify("collar-0417", offline, card.mac(offline)))
print("   the card itself still MACs fine - it is healthy, just orphaned")
