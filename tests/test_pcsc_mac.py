import ctypes as C
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from pcsc_mac import CardConnection, IORequest, PCSCError, U32, exchange


class ExchangeTests(unittest.TestCase):
    def run_trace(self, replies, expected_commands, expected):
        commands = []
        def raw(command):
            commands.append(command)
            return bytes.fromhex(replies[len(commands) - 1])
        self.assertEqual(exchange(raw, expected_commands[0], has_le=False), expected)
        self.assertEqual(commands, expected_commands)

    def test_chained_payload_survives_get_response_length_retry(self):
        initial = [0x80, 0x32, 0, 0, 1, 0xAB]
        self.run_trace(["AABB6102", "6C03", "CCDDEE9000"],
                       [initial, [0, 0xC0, 0, 0, 2], [0, 0xC0, 0, 0, 3]],
                       ("9000", bytes.fromhex("AABBCCDDEE")))

    def test_case3_retry_preserves_final_data_byte_then_chains(self):
        initial = [0x80, 0x32, 0, 0, 1, 0xAB]
        self.run_trace(["6C00", "116100", "229000"],
                       [initial, initial + [0], [0, 0xC0, 0, 0, 0]],
                       ("9000", b"\x11\x22"))

    def test_repeated_length_retry_changes_le_not_data(self):
        initial = [0x80, 0x32, 0, 0, 1, 0xAB]
        self.run_trace(["6C02", "6C03", "9000"],
                       [initial, initial + [2], initial + [3]], ("9000", b""))

    def test_all_28_init_update_bytes_survive_chaining(self):
        payload = bytes(range(28))
        replies = iter([payload[:10] + b"\x61\x12", payload[10:] + b"\x90\x00"])
        self.assertEqual(exchange(lambda _: next(replies), [0, 0x50, 0, 0, 0]),
                         ("9000", payload))

    def test_short_reply_and_endless_continuation_fail(self):
        for reply in (b"", b"\x90", b"\x61\x01", b"\x6c\x01"):
            with self.subTest(reply=reply), self.assertRaises(RuntimeError):
                exchange(lambda _: reply, [0, 0xC0, 0, 0, 1])


class BindingTests(unittest.TestCase):
    def library(self, connect_rc=0):
        lib = Mock()
        def establish(_, a, b, context):
            C.cast(context, C.POINTER(U32))[0] = 7
            return 0
        def readers(context, groups, buffer, length):
            if buffer is not None:
                C.memmove(buffer, b"Reader\0\0", 8)
            C.cast(length, C.POINTER(U32))[0] = 8
            return 0
        def connect(context, reader, share, protocols, handle, protocol):
            if not connect_rc:
                C.cast(handle, C.POINTER(U32))[0] = 9
                C.cast(protocol, C.POINTER(U32))[0] = 1
            return connect_rc
        lib.SCardEstablishContext.side_effect = establish
        lib.SCardListReaders.side_effect = readers
        lib.SCardConnect.side_effect = connect
        lib.SCardDisconnect.return_value = lib.SCardReleaseContext.return_value = 0
        return lib

    def test_failed_connect_releases_context_without_transmit(self):
        lib = self.library(-2146434970)  # 0x80100066
        with self.assertRaises(PCSCError) as cm:
            CardConnection(lib)
        self.assertEqual(cm.exception.rc, 0x80100066)
        lib.SCardReleaseContext.assert_called_once()
        lib.SCardTransmit.assert_not_called()
        lib.SCardDisconnect.assert_not_called()

    def test_list_failure_releases_context(self):
        lib = self.library()
        lib.SCardListReaders.side_effect = None
        lib.SCardListReaders.return_value = -2146435026
        with self.assertRaises(PCSCError):
            CardConnection(lib)
        lib.SCardReleaseContext.assert_called_once()

    def test_abi_cleanup_and_transmit_error(self):
        lib = self.library()
        with CardConnection(lib) as card:
            self.assertEqual(C.sizeof(card.handle), 4)
            self.assertEqual(C.sizeof(IORequest), 8)
            self.assertEqual(len(lib.SCardTransmit.argtypes), 7)
            lib.SCardTransmit.return_value = -2146435050  # 0x80100016
            with self.assertRaises(PCSCError):
                card.raw([0, 0xA4, 4, 0, 0])
        card.close()
        lib.SCardDisconnect.assert_called_once()
        lib.SCardReleaseContext.assert_called_once()


if __name__ == "__main__":
    unittest.main()
