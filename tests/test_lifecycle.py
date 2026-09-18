import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))
from collar_lifecycle import Backend, CardStub, TRANSPORT_KEY, cmac_tag


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.key = bytes(range(16))
        self.card, self.backend = CardStub(), Backend()
        self.packet = self.key + cmac_tag(TRANSPORT_KEY, self.key)
        self.card.personalize(self.packet)
        self.backend.enroll("device", self.key)

    def test_one_shot_and_rejection_preserves_key(self):
        before = self.card.mac(b"hello")
        with self.assertRaises(ValueError):
            self.card.personalize(self.packet)
        self.assertEqual(self.card.mac(b"hello"), before)

    def test_wrong_personalization_tag(self):
        card = CardStub()
        with self.assertRaises(ValueError):
            card.personalize(self.packet[:-1] + bytes([self.packet[-1] ^ 1]))
        self.assertIsNone(card.device_key)

    def test_mac_tag_cannot_authorize_rotation(self):
        chosen = b"X" * 16
        with self.assertRaises(ValueError):
            self.card.rotate(chosen + self.card.mac(chosen))
        self.assertEqual(self.card.device_key, self.key)

    def test_unsolicited_challenge_and_replay(self):
        forged = b"\0\0\0\x10" + b"X" * 8
        self.assertNotEqual(self.backend.verify("device", forged, self.card.mac(forged)), "accepted")
        ch = self.backend.challenge("device")
        tag = self.card.mac(ch)
        self.assertEqual(self.backend.verify("device", ch, tag), "accepted")
        self.assertNotEqual(self.backend.verify("device", ch, tag), "accepted")

    def test_new_challenge_invalidates_previous_one(self):
        first = self.backend.challenge("device")
        self.backend.challenge("device")
        self.assertNotEqual(self.backend.verify("device", first, self.card.mac(first)), "accepted")

    def test_rotation_waits_for_new_key_confirmation(self):
        packet, confirmation = self.backend.prepare_rotation("device")
        with self.assertRaises(ValueError):
            self.backend.finish_rotation("device", self.card.mac(confirmation))
        self.assertEqual(self.backend.registry["device"]["key"], self.key)
        self.card.rotate(packet)
        self.backend.finish_rotation("device", self.card.mac(confirmation))
        ch = self.backend.challenge("device")
        self.assertEqual(self.backend.verify("device", ch, self.card.mac(ch)), "accepted")

    def test_revoke_rejects_outstanding_response(self):
        ch = self.backend.challenge("device")
        self.backend.revoke("device")
        self.assertIn("revoked", self.backend.verify("device", ch, self.card.mac(ch)))
        with self.assertRaises(ValueError):
            self.backend.challenge("device")

    def test_lengths(self):
        for size in (0, 64):
            with self.subTest(size=size), self.assertRaises(ValueError):
                self.card.mac(b"x" * size)
        for size in (0, 31, 33):
            with self.subTest(size=size), self.assertRaises(ValueError):
                self.card.rotate(b"x" * size)


if __name__ == "__main__":
    unittest.main()
