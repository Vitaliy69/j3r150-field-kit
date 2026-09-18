#!/usr/bin/env python3
"""In-memory lifecycle demo; run with Python 3 and cryptography installed.
CardStub models command checks, not a secure memory boundary. Key transfers
carry plaintext plus a MAC. This is not a persistent backend service.
"""
import hmac
import os
import struct
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms

CTX_MAC, CTX_ROTATE = b"\x01", b"\x02"
TRANSPORT_KEY = bytes.fromhex("404142434445464748494A4B4C4D4E4F")


def cmac_tag(key, data):
    c = cmac.CMAC(algorithms.AES(key))
    c.update(data)
    return c.finalize()


class CardStub:
    def __init__(self):
        self.device_key = None

    def personalize(self, packet):
        if self.device_key is not None:
            raise ValueError("already personalized")
        if len(packet) != 32:
            raise ValueError("expected 16-byte key and 16-byte tag")
        key, tag = packet[:16], packet[16:]
        if not hmac.compare_digest(cmac_tag(TRANSPORT_KEY, key), tag):
            raise ValueError("transport MAC failed")
        self.device_key = key

    def mac(self, message):
        if self.device_key is None or not 1 <= len(message) <= 63:
            raise ValueError("MAC needs personalization and 1..63 bytes")
        return cmac_tag(self.device_key, CTX_MAC + message)

    def rotate(self, packet):
        if self.device_key is None or len(packet) != 32:
            raise ValueError("rotation needs personalization and 32 bytes")
        key, tag = packet[:16], packet[16:]
        if not hmac.compare_digest(cmac_tag(self.device_key, CTX_ROTATE + key), tag):
            raise ValueError("rotation MAC failed")
        self.device_key = key


class Backend:
    def __init__(self):
        self.registry = {}

    def enroll(self, device, key):
        if device in self.registry or len(key) != 16:
            raise ValueError("duplicate device or wrong key length")
        self.registry[device] = dict(key=key, counter=1, revoked=False,
                                     challenge=None, rotation=None)

    def challenge(self, device):
        rec = self.registry[device]
        if rec["revoked"]:
            raise ValueError("device revoked")
        payload = struct.pack(">I", rec["counter"]) + os.urandom(8)
        rec["challenge"] = payload  # one outstanding challenge per device
        return payload

    def verify(self, device, payload, tag):
        rec = self.registry.get(device)
        if rec is None or rec["revoked"]:
            return "REJECTED: unknown or revoked device"
        if len(payload) != 12 or payload != rec["challenge"]:
            return "REJECTED: challenge not outstanding"
        if not hmac.compare_digest(cmac_tag(rec["key"], CTX_MAC + payload), tag):
            return "REJECTED: bad MAC"
        rec["counter"] += 1
        rec["challenge"] = None
        return "accepted"

    def prepare_rotation(self, device):
        rec = self.registry[device]
        if rec["revoked"] or rec["rotation"] is not None:
            raise ValueError("revoked device or rotation already pending")
        key, confirmation = os.urandom(16), os.urandom(16)
        rec["rotation"] = (key, confirmation)
        return key + cmac_tag(rec["key"], CTX_ROTATE + key), confirmation

    def finish_rotation(self, device, confirmation_tag):
        rec = self.registry[device]
        if rec["revoked"] or rec["rotation"] is None:
            raise ValueError("no active rotation")
        key, challenge = rec["rotation"]
        if not hmac.compare_digest(cmac_tag(key, CTX_MAC + challenge), confirmation_tag):
            raise ValueError("new key not confirmed")
        rec.update(key=key, rotation=None, challenge=None)

    def revoke(self, device):
        self.registry[device].update(revoked=True, challenge=None, rotation=None)


def main():
    card, backend = CardStub(), Backend()
    device, key = "collar-0417", os.urandom(16)
    card.personalize(key + cmac_tag(TRANSPORT_KEY, key))
    backend.enroll(device, key)
    print("1) personalized at production, enrolled on backend")
    for i in range(2):
        challenge = backend.challenge(device)
        print("2) auth:", backend.verify(device, challenge, card.mac(challenge)),
              f"(round {i + 1})")
    forged_key = os.urandom(16)
    try:
        card.rotate(forged_key + card.mac(forged_key))
    except ValueError:
        print("3) forgery via plain MAC rejected (domain separation holds)")
    else:
        raise RuntimeError("FORGERY ACCEPTED")
    packet, confirmation = backend.prepare_rotation(device)
    card.rotate(packet)
    backend.finish_rotation(device, card.mac(confirmation))
    print("   rotated: card and backend both hold fresh keys")
    challenge = backend.challenge(device)
    print("4) auth with fresh key:", backend.verify(device, challenge, card.mac(challenge)))
    backend.revoke(device)
    offline = struct.pack(">I", 9) + os.urandom(8)
    print("5) after revocation:", backend.verify(device, offline, card.mac(offline)))
    print("   the card itself still MACs fine - it is healthy, just orphaned")


if __name__ == "__main__":
    main()
