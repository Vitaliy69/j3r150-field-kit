"""Apple PC/SC ABI and short-APDU transport shared by the bench clients."""
import atexit
import ctypes as C
import sys

U32 = C.c_uint32


class IORequest(C.Structure):
    _fields_ = [("dwProtocol", U32), ("cbPciLength", U32)]


class PCSCError(RuntimeError):
    def __init__(self, operation, rc):
        self.rc = int(rc) & 0xffffffff
        super().__init__(f"{operation} rc={self.rc:#010x} (PC/SC, not an APDU status)")


def checked(operation, rc):
    if rc:
        raise PCSCError(operation, rc)


def exchange(raw, apdu, has_le=True):
    """Return (SW, payload), retaining earlier chunks across 61 -> 6C."""
    command = list(apdu)
    payload = bytearray()
    for _ in range(32):
        reply = raw(command)
        if len(reply) < 2:
            raise RuntimeError("PC/SC returned fewer than two status bytes")
        body, sw1, sw2 = reply[:-2], reply[-2], reply[-1]
        if sw1 == 0x6C:
            command = command[:-1] + [sw2] if has_le else command + [sw2]
            has_le = True
            continue
        payload.extend(body)
        if sw1 == 0x61:
            command = [0x00, 0xC0, 0x00, 0x00, sw2]  # 00 means 256
            has_le = True
            continue
        return f"{sw1:02X}{sw2:02X}", bytes(payload)
    raise RuntimeError("APDU continuation limit reached; stop this session")


class CardConnection:
    def __init__(self, library=None):
        self.context = U32()
        self.handle = U32()
        self.protocol = U32()
        self.lib = library or C.CDLL("/System/Library/Frameworks/PCSC.framework/PCSC")
        # Apple's DWORD, LONG, SCARDCONTEXT and SCARDHANDLE are 32-bit,
        # including on arm64. Unix unsigned long is not a substitute.
        signatures = {
            "SCardEstablishContext": [U32, C.c_void_p, C.c_void_p, C.POINTER(U32)],
            "SCardListReaders": [U32, C.c_char_p, C.c_void_p, C.POINTER(U32)],
            "SCardConnect": [U32, C.c_char_p, U32, U32, C.POINTER(U32), C.POINTER(U32)],
            "SCardStatus": [U32, C.c_void_p, C.POINTER(U32), C.POINTER(U32),
                            C.POINTER(U32), C.c_void_p, C.POINTER(U32)],
            "SCardTransmit": [U32, C.POINTER(IORequest), C.c_void_p, U32,
                              C.POINTER(IORequest), C.c_void_p, C.POINTER(U32)],
            "SCardDisconnect": [U32, U32],
            "SCardReleaseContext": [U32],
        }
        for name, args in signatures.items():
            fn = getattr(self.lib, name)
            fn.argtypes, fn.restype = args, C.c_int32
        if C.sizeof(IORequest) != 8:
            raise RuntimeError("SCARD_IO_REQUEST must be 8 bytes on Apple PC/SC")
        try:
            checked("SCardEstablishContext", self.lib.SCardEstablishContext(
                0, None, None, C.byref(self.context)))
            length = U32()
            checked("SCardListReaders(size)", self.lib.SCardListReaders(
                self.context, None, None, C.byref(length)))
            if length.value < 2:
                raise RuntimeError("No smartcard reader found")
            readers = C.create_string_buffer(length.value)
            checked("SCardListReaders", self.lib.SCardListReaders(
                self.context, None, readers, C.byref(length)))
            names = [name for name in readers.raw.split(b"\0") if name]
            if not names:
                raise RuntimeError("No smartcard reader found")
            self.reader = names[0].decode()
            print("Reader:", self.reader)
            rc = self.lib.SCardConnect(self.context, names[0], 2, 3,
                                      C.byref(self.handle), C.byref(self.protocol))
            protocol = {1: "T=0", 2: "T=1"}.get(self.protocol.value, "not negotiated")
            print(f"SCardConnect: {rc & 0xffffffff:#010x} | proto: {protocol}")
            checked("SCardConnect", rc)
            if not self.handle.value:
                raise RuntimeError("SCardConnect returned no handle")
        except BaseException:
            self.close()
            raise
        atexit.register(self.close)

    def raw(self, apdu):
        if not self.handle.value:
            raise RuntimeError("Card connection is closed")
        data = bytes(apdu)
        send = C.create_string_buffer(data, len(data))
        recv = C.create_string_buffer(258)
        length = U32(len(recv))
        pci = IORequest(self.protocol.value, C.sizeof(IORequest))
        checked("SCardTransmit", self.lib.SCardTransmit(
            self.handle, C.byref(pci), send, len(data), None, recv, C.byref(length)))
        if length.value > len(recv):
            raise RuntimeError("SCardTransmit returned an oversized length")
        return recv.raw[:length.value]

    def transmit(self, apdu, label="", has_le=True):
        sw, payload = exchange(self.raw, apdu, has_le)
        print(f"{label:38s} -> SW {sw}")
        return sw, payload

    def atr(self):
        reader = C.create_string_buffer(1024)
        reader_len, state, protocol = U32(len(reader)), U32(), U32()
        atr = C.create_string_buffer(64)
        atr_len = U32(len(atr))
        checked("SCardStatus", self.lib.SCardStatus(
            self.handle, reader, C.byref(reader_len), C.byref(state),
            C.byref(protocol), atr, C.byref(atr_len)))
        if atr_len.value > len(atr):
            raise RuntimeError("SCardStatus returned an oversized ATR")
        return atr.raw[:atr_len.value]

    def close(self):
        # Release the context even if disconnect fails; close is idempotent.
        if self.handle.value:
            rc = self.lib.SCardDisconnect(self.handle, 0)  # LEAVE_CARD
            self.handle.value = 0
            if rc:
                print(PCSCError("SCardDisconnect", rc), file=sys.stderr)
        if self.context.value:
            rc = self.lib.SCardReleaseContext(self.context)
            self.context.value = 0
            if rc:
                print(PCSCError("SCardReleaseContext", rc), file=sys.stderr)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
