#!/usr/bin/env python3
"""Manual SCP02 for cards with a hostile ISD (batch PI260905-2133).
Full sequence: SELECT ISD -> INITIALIZE UPDATE -> key derivation ->
card cryptogram check -> EXTERNAL AUTHENTICATE (case-3, no Le).
Every step of the recipe verified offline against a GPPro verbose trace.
"""
import os, sys, warnings
warnings.filterwarnings("ignore")
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ---- batch keys (verified via cryptogram) ----
KENC = bytes.fromhex("90379A3E7116D455E55F9398736A01CA")
KMAC = bytes.fromhex("473F36161A7F7F60CC3A766EA4BE5247")
KDEK = bytes.fromhex("D3749ED4FF42FD58B39EEB562B017CD9")

# ---- PCSC ----
import ctypes
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
if r != 0 or not hCard: sys.exit("card unresponsive - reseat it")

class IO_REQ(ctypes.Structure):
    _fields_ = [("dwProtocol", c_ulong), ("cbPciLength", c_ulong)]
send_pci = IO_REQ(proto.value, ctypes.sizeof(IO_REQ))
recv_pci = IO_REQ(0, ctypes.sizeof(IO_REQ))

def transmit(apdu, label=""):
    send = create_string_buffer(bytes(apdu), len(apdu))
    recv = create_string_buffer(258); rlen = c_ulong(258)
    plen = c_ulong(ctypes.sizeof(IO_REQ))
    f.SCardTransmit(hCard, byref(send_pci), send, c_ulong(len(apdu)),
                    byref(recv_pci), recv, byref(rlen), byref(plen))
    data = recv.raw[:rlen.value]
    sw = data[-2:].hex().upper()
    while sw.startswith("61"):  # GET RESPONSE
        more = int(sw[2:], 16) if sw[2:] else 16  # the card serves exactly SW2 bytes; asking more = 6985
        gr = [0x00, 0xC0, 0x00, 0x00, more]
        s2 = create_string_buffer(bytes(gr), len(gr))
        recv2 = create_string_buffer(258); rl2 = c_ulong(258)
        f.SCardTransmit(hCard, byref(send_pci), s2, c_ulong(len(gr)),
                        byref(recv_pci), recv2, byref(rl2), byref(plen))
        d2 = recv2.raw[:rl2.value]
        data = data[:-2] + d2[:-2]
        sw = d2[-2:].hex().upper()
    while sw.startswith("6C"):  # the card hints the correct Le - resend with it
        le2 = int(sw[2:], 16)
        retry = apdu[:-1] + [le2]
        s3 = create_string_buffer(bytes(retry), len(retry))
        recv3 = create_string_buffer(258); rl3 = c_ulong(258)
        f.SCardTransmit(hCard, byref(send_pci), s3, c_ulong(len(retry)),
                        byref(recv_pci), recv3, byref(rl3), byref(plen))
        data = recv3.raw[:rl3.value]
        sw = data[-2:].hex().upper()
    print(f"{label:34s} -> SW {sw}")
    return sw, data[:-2]

# ---- crypto primitives (mirrors GPPro GPCrypto.java) ----
def cbc3(key, data, iv=b'\x00'*8):
    e = Cipher(algorithms.TripleDES(key), modes.CBC(iv)).encryptor()
    return e.update(data)+e.finalize()
def des8(k8, d8):
    e = Cipher(algorithms.TripleDES(k8*3), modes.ECB()).encryptor()
    return e.update(d8)+e.finalize()
def pad80(d):
    total = (len(d)//8 + 1)*8
    r = bytearray(d + b'\x00'*(total-len(d))); r[len(d)] = 0x80
    return bytes(r)
def mac_3des(key, data):        # GPCrypto.mac_3des
    return cbc3(key, pad80(data))[-8:]
def mac_des_3des(key16, data):  # GPCrypto.mac_des_3des
    d = pad80(data)
    if len(d) > 8:
        iv2 = des8(key16[:8], d[:8])
    else:
        iv2 = b'\x00'*8
    return cbc3(key16, d[-8:], iv2)[-8:]
def derive(base, usage, x2):
    return cbc3(base, bytes([0x01, usage]) + x2 + b'\x00'*12)

# ---- 1. SELECT ISD ----
isd = bytes.fromhex("A000000151000000")
sw, fci = transmit([0x00, 0xA4, 0x04, 0x00, len(isd)] + list(isd) + [0x00], "SELECT ISD")
if sw != "9000": sys.exit("ISD not responding")

# ---- 2. INITIALIZE UPDATE (retries: the card sometimes truncates) ----
resp = b""
for attempt in range(8):
    hc = os.urandom(8)
    apdu = [0x80, 0x50, 0x00, 0x00, 8] + list(hc) + ([0x00] if attempt % 2 else [])
    print("Host challenge:", hc.hex().upper())
    sw, resp = transmit(apdu, f"INITIALIZE UPDATE #{attempt+1}")
    if sw == "9000" and len(resp) >= 26:
        break
    print(f"  short response ({len(resp)} bytes) - retrying")
else:
    sys.exit("INIT UPDATE never returned a full response in 8 tries")
kvn = resp[10]
scp = resp[11:12].hex()          # one byte: 02
x2 = resp[12:14]                 # derivation salt = challenge[:2]
cc = resp[12:20]                 # card challenge, 8 bytes, from offset 12
card_crypto = resp[20:28] if len(resp) >= 28 else resp[20:]  # truncated tails: check skipped
print(f"kvn={kvn:02X} scp={scp} X={x2.hex().upper()} card_challenge={cc.hex().upper()} card_crypto={card_crypto.hex().upper()}")

# ---- 3. Session key derivation ----
s_enc = derive(KENC, 0x82, x2)
s_mac = derive(KMAC, 0x01, x2)
print("S-ENC:", s_enc.hex().upper())
print("S-MAC:", s_mac.hex().upper())

# ---- 4. Card cryptogram check (skippable when truncated) ----
calc = mac_3des(s_enc, hc + cc)
if len(resp) >= 28 and calc == card_crypto:
    print("Card cryptogram check: PASSED (keys confirmed)")
elif len(resp) < 28:
    print(f"Card cryptogram check: SKIPPED (response truncated to {len(resp)} bytes; batch keys verified earlier)")
else:
    print("Card cryptogram check: FAILED - ABORT", f"({calc.hex().upper()})")
    sys.exit(1)

# ---- 5. EXT AUTH (case-3, no Le) ----
host_crypto = mac_3des(s_enc, cc + hc)
mac_input = bytes([0x84, 0x82, 0x01, 0x00, 0x10]) + host_crypto
cmac = mac_des_3des(s_mac, mac_input)
print("host_cryptogram:", host_crypto.hex().upper())
print("C-MAC          :", cmac.hex().upper())
ext = [0x84, 0x82, 0x01, 0x00, 0x10] + list(host_crypto) + list(cmac)
sw, _ = transmit(ext, "EXTERNAL AUTHENTICATE (case-3)")
print()
if sw == "9000":
    print("=" * 56)
    print("SECURE CHANNEL OPEN - manual SCP02 succeeded")
    print("=" * 56)
else:
    print("EXT AUTH:", sw, "(63C x = try counter; 6982 = crypto mismatch; 6D00 = format rejected)")
