#!/usr/bin/env python3
# EXT AUTH format probe - maps what the ISD's dispatcher actually accepts.
# Sacrificial card only: dummy payloads, no valid crypto. Card #1 (keyed, unusable without this).
import ctypes, sys
from ctypes import c_void_p, c_ulong, byref, create_string_buffer

f = ctypes.CDLL("/System/Library/Frameworks/PCSC.framework/PCSC")
ctx = c_void_p()
f.SCardEstablishContext(0, None, None, byref(ctx))
pcch = c_ulong(0)
f.SCardListReaders(ctx, None, None, byref(pcch))
buf = create_string_buffer(pcch.value)
f.SCardListReaders(ctx, None, buf, byref(pcch))
names = [x.decode() for x in buf.raw.split(b"\x00") if x]
print("Reader:", names[0] if names else "NOT FOUND")
if not names: sys.exit(1)

hCard = c_void_p(); proto = c_ulong()
r = f.SCardConnect(ctx, names[0].encode(), 2, 3, byref(hCard), byref(proto))
print("SCardConnect:", hex(r), "| proto:", "T=0" if proto.value == 1 else "T=1")
if r != 0 or not hCard: sys.exit("...")

class IO_REQ(ctypes.Structure):
    _fields_ = [("dwProtocol", c_ulong), ("cbPciLength", c_ulong)]
send_pci = IO_REQ(proto.value, ctypes.sizeof(IO_REQ))
recv_pci = IO_REQ(0, ctypes.sizeof(IO_REQ))

def transmit(apdu, label):
    send = create_string_buffer(bytes(apdu), len(apdu))
    recv = create_string_buffer(258); rlen = c_ulong(258)
    plen = c_ulong(ctypes.sizeof(IO_REQ))
    f.SCardTransmit(hCard, byref(send_pci), send, c_ulong(len(apdu)),
                    byref(recv_pci), recv, byref(rlen), byref(plen))
    data = recv.raw[:rlen.value]
    sw = data[-2:].hex().upper()
    # ... GET RESPONSE
    while sw.startswith("61"):
        more = int(sw[2:], 16) if sw[2:] else 16
        gr = [0x00, 0xC0, 0x00, 0x00, more] if more else [0x00, 0xC0, 0x00, 0x00]
        send = create_string_buffer(bytes(gr), len(gr))
        recv = create_string_buffer(258); rlen = c_ulong(258)
        plen = c_ulong(ctypes.sizeof(IO_REQ))
        f.SCardTransmit(hCard, byref(send_pci), send, c_ulong(len(gr)),
                        byref(recv_pci), recv, byref(rlen), byref(plen))
        d2 = recv.raw[:rlen.value]
        data = data[:-2] + d2[:-2] + d2[-2:]
        sw = d2[-2:].hex().upper()
    print(f"{label:52s} -> SW {sw}")
    return sw, data[:-2]

# SELECT ISD
isd = bytes.fromhex("A000000151000000")
transmit([0x00, 0xA4, 0x04, 0x00, len(isd)] + list(isd) + [0x00], "SELECT ISD")

# INITIALIZE UPDATE (host challenge = fixed for reproducibility)
hc = bytes.fromhex("0102030405060708")
sw, resp = transmit([0x80, 0x50, 0x00, 0x00, 8] + list(hc) + [0x00], "INITIALIZE UPDATE 80 50")
if sw != "9000":
    print("INIT UPDATE failed:", sw, "- ...reseat..."); sys.exit(1)
print("  INIT UPDATE resp:", resp.hex().upper())

dummy16 = bytes.fromhex("00112233445566778899AABBCCDDEEFF")

variants = [
    ([0x84, 0x82, 0x01, 0x00, 16] + list(dummy16),          "EXT AUTH 84 82 P1=01 case-3 (no Le)"),
    ([0x84, 0x82, 0x01, 0x00, 16] + list(dummy16) + [0x00], "EXT AUTH 84 82 P1=01 case-4 (Le=00, how GPPro)"),
    ([0x80, 0x82, 0x01, 0x00, 16] + list(dummy16),          "EXT AUTH 80 82 P1=01 case-3 (CLA=80)"),
    ([0x80, 0x82, 0x01, 0x00, 16] + list(dummy16) + [0x00], "EXT AUTH 80 82 P1=01 case-4 (CLA=80)"),
    ([0x84, 0x82, 0x00, 0x00, 16] + list(dummy16),          "EXT AUTH 84 82 P1=00 case-3"),
    ([0x00, 0x82, 0x01, 0x00, 16] + list(dummy16),          "EXT AUTH 00 82 P1=01 case-3 (CLA=00)"),
]
print()
for apdu, label in variants:
    sw, _ = transmit(apdu, label)
    if sw == "6D00":
        continue  # ...
    print(f"\n*** ...D00 response ...{label} -> SW {sw} ***")
    print("*** 63C x = .../6984 = ...error (...A86 = P1 ...***")
    break
print("\n(card ...reseat...")
