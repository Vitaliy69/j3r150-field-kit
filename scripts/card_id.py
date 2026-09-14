#!/usr/bin/env python3
# J3R150 arrival check v2 - RUN-day pre-flight. READ-ONLY: SELECT only, factory keys untouched.
import ctypes
from ctypes import c_void_p, c_char_p, c_ulong, byref, create_string_buffer

f = ctypes.CDLL("/System/Library/Frameworks/PCSC.framework/PCSC")
ctx = c_void_p()
f.SCardEstablishContext(0, None, None, byref(ctx))

pcch = c_ulong(0)
f.SCardListReaders(ctx, None, None, byref(pcch))
buf = create_string_buffer(pcch.value)
f.SCardListReaders(ctx, None, buf, byref(pcch))
names = [x.decode() for x in buf.raw.split(b"\x00") if x]
print("Reader:", names[0] if names else "NOT FOUND")
if not names:
    raise SystemExit("no reader found")

hCard = c_void_p(); proto = c_ulong()
r = f.SCardConnect(ctx, names[0].encode(), 2, 3, byref(hCard), byref(proto))
print("SCardConnect:", hex(r), "| proto:", "T=0" if proto.value == 1 else "T=1")
if r != 0 or not hCard:
    raise SystemExit("card unresponsive - reseat it, chip first")

atr = create_string_buffer(64); alen = c_ulong(64)
rn = create_string_buffer(256); rlen_r = c_ulong(256)
state = c_ulong()
f.SCardStatus(hCard, rn, byref(rlen_r), byref(state), byref(proto), atr, byref(alen))
print("ATR:", atr.raw[:alen.value].hex().upper())

class IO_REQ(ctypes.Structure):
    _fields_ = [("dwProtocol", c_ulong), ("cbPciLength", c_ulong)]
send_pci = IO_REQ(proto.value, ctypes.sizeof(IO_REQ))
recv_pci = IO_REQ(0, ctypes.sizeof(IO_REQ))

def transmit(apdu):
    send = create_string_buffer(bytes(apdu), len(apdu))
    recv = create_string_buffer(258); rlen = c_ulong(258)
    plen = c_ulong(ctypes.sizeof(IO_REQ))
    f.SCardTransmit(hCard, byref(send_pci), send, c_ulong(len(apdu)),
                    byref(recv_pci), recv, byref(rlen), byref(plen))
    data = recv.raw[:rlen.value]
    return data[:-2], data[-2:].hex().upper()

ISD = "A000000151000000"  # Issuer Security Domain - card manager of any GlobalPlatform card
apdu = [0x00, 0xA4, 0x04, 0x00, len(bytes.fromhex(ISD))] + list(bytes.fromhex(ISD)) + [0x00]
data, sw = transmit(apdu)
# 61xx = "more data available" - fetch it via GET RESPONSE (this is FCI, not an error)
while sw.startswith("61"):
    more = int(sw[2:], 16)
    data2, sw = transmit([0x00, 0xC0, 0x00, 0x00] + ([more] if more else []))
    data = data + data2

print(f"SELECT ISD {ISD} -> SW {sw}")
print()
if sw == "9000" and data:
    print(f"ISD FCI ({len(data)} bytes): {data.hex().upper()}")
    print("VERDICT: card alive, GlobalPlatform ISD present (keyset proven at authentication).")
    print("(read-only: SELECT only, factory dev keys NOT used, NOT changed)")
else:
    print(f"VERDICT: SW {sw} - reseat the card and run again.")
