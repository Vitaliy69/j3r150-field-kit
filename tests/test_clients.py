"""Exercise CLI setup with a fake connection; never touch PC/SC or hardware."""
import runpy
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import pcsc_mac


class ClientTests(unittest.TestCase):
    def test_archived_probes_do_not_connect(self):
        for name, stage in (("probe_extauth.py", ""), ("gp_lite.py", "install03"),
                            ("gp_lite.py", "installfix")):
            with self.subTest(name=name, stage=stage), \
                    patch.object(pcsc_mac, "CardConnection") as connect, \
                    patch.object(sys, "argv", [name, stage]):
                with self.assertRaises(SystemExit):
                    runpy.run_path(str(ROOT / "scripts" / name), run_name="__main__")
                connect.assert_not_called()

    def run_bad_handshake(self, name, response):
        card = Mock()
        card.transmit.side_effect = [("9000", b""), ("9000", response)]
        with patch.object(pcsc_mac, "CardConnection", return_value=card), \
                patch.object(sys, "argv", [name, "open"]):
            with self.assertRaises(SystemExit):
                runpy.run_path(str(ROOT / "scripts" / name), run_name="__main__")
        self.assertEqual(card.transmit.call_count, 2)
        for call in card.transmit.call_args_list:
            self.assertNotEqual(call.args[0][1], 0x82, "EXT AUTH sent after invalid response")

    def test_bad_cryptogram_never_reaches_ext_auth(self):
        for name in ("open_channel.py", "gp_lite.py"):
            with self.subTest(client=name):
                self.run_bad_handshake(name, b"\0" * 28)

    def test_wrong_payload_length_stops_both_clients(self):
        for name in ("open_channel.py", "gp_lite.py"):
            for size in (0, 26, 29):
                with self.subTest(client=name, size=size):
                    self.run_bad_handshake(name, b"\0" * size)


if __name__ == "__main__":
    unittest.main()
