"""Load pure helpers by AST; importing the CLI would connect to a real card."""
import ast
import os
import unittest
from pathlib import Path


def helpers():
    tree = ast.parse((Path(__file__).resolve().parents[1] / "scripts/gp_lite.py").read_text())
    names = {"get_status", "raw_status", "standard_install_data", "install_for_load",
             "make_secure_tx", "open_channel", "make_selectable_data"}
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    scope = {"PKG_AID": bytes.fromhex("F000000001DEAD"),
             "APP_AID_BYTES": bytes.fromhex("F000000001DEAD01"),
             "APP_AID": bytes.fromhex("F000000001DEAD02")}
    exec(compile(ast.Module(body=functions, type_ignores=[]), "gp_lite helpers", "exec"), scope)
    return scope


class InstallerTests(unittest.TestCase):
    def test_make_selectable_has_all_standard_slots(self):
        self.assertEqual(helpers()["make_selectable_data"]().hex().upper(),
                         "000008F000000001DEAD0201000000")

    def test_instance_changes_without_changing_module(self):
        scope = helpers()
        for instance in ("F000000001DEAD02", "F000000001DEAD0304"):
            scope["APP_AID"] = bytes.fromhex(instance)
            packet = scope["standard_install_data"]()
            fields = []
            while packet:
                n = packet[0]
                fields.append(packet[1:1+n])
                packet = packet[1+n:]
            self.assertEqual(fields[1], bytes.fromhex("F000000001DEAD01"))
            self.assertEqual(fields[2], bytes.fromhex(instance))
            self.assertEqual(fields[3:], [b"\x00", b"\xc9\x00", b""])

    def test_install_for_load_has_five_fields(self):
        commands = []
        helpers()["install_for_load"](lambda *args: commands.append(args))
        self.assertEqual(commands[0][3].hex().upper(),
                         "07F000000001DEAD08A000000151000000000000")

    def test_registry_continuation_and_status(self):
        commands = []
        replies = iter([("9000", b"isd"), ("9000", b"app"),
                        ("6310", b"first"), ("9000", b"second")])
        def send(*args):
            commands.append(args)
            return next(replies)
        self.assertEqual(helpers()["get_status"](send), ("9000", b"isdappfirstsecond"))
        self.assertEqual([(x[1], x[2]) for x in commands],
                         [(0x80, 2), (0x40, 2), (0x20, 2), (0x20, 3)])

    def test_6310_advances_secure_chain(self):
        scope = helpers()
        scope.update(des1_ecb=lambda key, iv: iv,
                     mac_des_3des_gpp=lambda key, data, iv: b"next-MAC",
                     transmit=lambda *a, **kw: ("6310", b"page"))
        send, state = scope["make_secure_tx"](b"key")
        state["icv"] = b"old-MAC!"
        send(0xF2, 0x20, 2)
        self.assertEqual(state["icv"], b"next-MAC")


if __name__ == "__main__":
    unittest.main()
