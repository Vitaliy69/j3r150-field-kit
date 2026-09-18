#!/usr/bin/env python3
"""Manual SCP02 for the J3R150 bench (batch PI260905-2133).
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

# ---- shared Apple PC/SC transport ----
from pcsc_mac import CardConnection
card_connection = CardConnection()
transmit = card_connection.transmit

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
sw, fci = transmit([0x00, 0xA4, 0x04, 0x00, len(isd)] + list(isd) + [0x00],
                    "SELECT ISD", has_le=True)
if sw != "9000": sys.exit("ISD not responding")

# ---- 2. INITIALIZE UPDATE ----
resp = b""
for attempt in range(8):
    hc = os.urandom(8)
    apdu = [0x80, 0x50, 0x00, 0x00, 8] + list(hc) + ([0x00] if attempt % 2 else [])
    print("Host challenge:", hc.hex().upper())
    has_le = bool(attempt % 2)   # case-4 variant carries the trailing Le byte
    sw, resp = transmit(apdu, f"INITIALIZE UPDATE #{attempt+1}", has_le=has_le)
    if sw == "9000":
        break
    print(f"  short response ({len(resp)} bytes) - retrying")
else:
    sys.exit("INIT UPDATE never returned a full response in 8 tries")
if len(resp) != 28:
    sys.exit(f"INIT UPDATE returned {len(resp)} bytes, expected 28")
kvn = resp[10]
scp = resp[11:12].hex()          # one byte: 02
x2 = resp[12:14]                 # derivation salt = challenge[:2]
cc = resp[12:20]                 # card challenge, 8 bytes, from offset 12
card_crypto = resp[20:28]
print(f"kvn={kvn:02X} scp={scp} X={x2.hex().upper()} card_challenge={cc.hex().upper()} card_crypto={card_crypto.hex().upper()}")

# ---- 3. Session key derivation ----
s_enc = derive(KENC, 0x82, x2)
s_mac = derive(KMAC, 0x01, x2)
print("S-ENC:", s_enc.hex().upper())
print("S-MAC:", s_mac.hex().upper())

# ---- 4. Card cryptogram check (mandatory: 28 bytes, verified) ----
if len(resp) != 28:
    sys.exit(f"INIT UPDATE returned {len(resp)} bytes, expected 28 - transport broken")
calc = mac_3des(s_enc, hc + cc)
if calc == card_crypto:
    print("Card cryptogram check: PASSED (keys confirmed)")
else:
    sys.exit("Card cryptogram MISMATCH - wrong keys or corrupted exchange")

# ---- 5. EXT AUTH (case-3, no Le) ----
host_crypto = mac_3des(s_enc, cc + hc)
mac_input = bytes([0x84, 0x82, 0x01, 0x00, 0x10]) + host_crypto
cmac = mac_des_3des(s_mac, mac_input)
print("host_cryptogram:", host_crypto.hex().upper())
print("C-MAC          :", cmac.hex().upper())
ext = [0x84, 0x82, 0x01, 0x00, 0x10] + list(host_crypto) + list(cmac)
sw, _ = transmit(ext, "EXTERNAL AUTHENTICATE (case-3)", has_le=False)
print()
if sw == "9000":
    print("=" * 56)
    print("SECURE CHANNEL OPEN - manual SCP02 succeeded")
    print("=" * 56)
else:
    sys.exit(f"EXT AUTH rejected: {sw}")
