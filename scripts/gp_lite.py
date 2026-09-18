#!/usr/bin/env python3
"""gp-lite: the smallest possible GlobalPlatform installer for the hostile
J3R150 batch. Stage `open`  = SCP02 handshake + GET STATUS (registry listing).
Stage `load`  = handshake + INSTALL for load + LOAD blocks + INSTALL for install
               + GET STATUS verification, one card session, C-MAC chained.
Stage `perso` = plain host transcript against the installed applet (no channel).
Command formats follow GP 2.2.1; crypto mirrors GPPro GPCrypto.java.
"""
import os, sys, zipfile, warnings
warnings.filterwarnings("ignore")
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import os as _os
_ks = _os.environ.get("GP_KEYSET", "batch").lower()
if _ks == "factory":
    _enc = _mac = "404142434445464748494A4B4C4D4E4F"   # factory test keys (kvn 01)
else:
    _enc, _mac = "90379A3E7116D455E55F9398736A01CA", "473F36161A7F7F60CC3A766EA4BE5247"
KENC = bytes.fromhex(_os.environ.get("GP_KENC", _enc))
KMAC = bytes.fromhex(_os.environ.get("GP_KMAC", _mac))
PKG_AID  = bytes.fromhex("F000000001DEAD")
APP_AID  = bytes.fromhex("F000000001DEAD01")
CAP_PATH = "build/cap/collarmac/javacard/collarmac.cap"
BLOCK    = 0xC0
COMPONENT_ORDER = ["Header", "Directory", "Applet", "Import", "ConstantPool",
                   "Class", "Method", "StaticField", "RefLocation", "Export", "Descriptor"]

# ---- PCSC transport (as in open_channel.py) ----
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

def raw(apdu):
    send = create_string_buffer(bytes(apdu), len(apdu))
    recv = create_string_buffer(258); rlen = c_ulong(258)
    plen = c_ulong(ctypes.sizeof(IO_REQ))
    f.SCardTransmit(hCard, byref(send_pci), send, c_ulong(len(apdu)),
                    byref(recv_pci), recv, byref(rlen), byref(plen))
    return recv.raw[:rlen.value]

def transmit(apdu, label=""):
    data = raw(apdu)
    sw = data[-2:].hex().upper()
    while sw.startswith("61"):
        more = int(sw[2:], 16) if sw[2:] else 16
        d2 = raw([0x00, 0xC0, 0x00, 0x00, more])
        data = data[:-2] + d2[:-2]
        sw = d2[-2:].hex().upper()
    while sw.startswith("6C"):
        le2 = int(sw[2:], 16)
        data = raw(apdu[:-1] + [le2])
        sw = data[-2:].hex().upper()
    print(f"{label:38s} -> SW {sw}")
    return sw, data[:-2]

# ---- crypto ----
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
def mac_3des(key, data): return cbc3(key, pad80(data))[-8:]
def mac_des_3des(key16, data):
    d = pad80(data)
    iv2 = des8(key16[:8], d[:8]) if len(d) > 8 else b'\x00'*8
    return cbc3(key16, d[-8:], iv2)[-8:]
def derive(base, usage, x2):
    return cbc3(base, bytes([0x01, usage]) + x2 + b'\x00'*12)

# ---- SCP02 handshake (from open_channel.py) ----
def open_channel(level=0x01):   # 0x01 = C-MAC, 0x03 = C-MAC + C-DECRYPTION
    isd = bytes.fromhex("A000000151000000")
    sw, _ = transmit([0x00, 0xA4, 0x04, 0x00, len(isd)] + list(isd) + [0x00], "SELECT ISD")
    if sw != "9000": sys.exit("ISD not responding - reseat the card")
    resp = b""
    for attempt in range(8):
        hc = os.urandom(8)
        apdu = [0x80, 0x50, 0x00, 0x00, 8] + list(hc) + ([0x00] if attempt % 2 else [])
        sw, resp = transmit(apdu, f"INITIALIZE UPDATE #{attempt+1}")
        if sw == "9000" and len(resp) >= 26: break
    else: sys.exit("INIT UPDATE failed 8 times - reseat")
    x2 = resp[12:14]; cc = resp[12:20]
    s_enc = derive(KENC, 0x82, x2); s_mac = derive(KMAC, 0x01, x2)
    host_crypto = mac_3des(s_enc, cc + hc)
    mac_input = bytes([0x84, 0x82, level, 0x00, 0x10]) + host_crypto
    cmac = mac_des_3des(s_mac, mac_input)
    ext = [0x84, 0x82, level, 0x00, 0x10] + list(host_crypto) + list(cmac)
    lbl = "EXTERNAL AUTHENTICATE (C-MAC+C-DECRYPT)" if level == 0x03 else "EXTERNAL AUTHENTICATE (C-MAC level)"
    sw, _ = transmit(ext, lbl)
    if sw != "9000": sys.exit("EXT AUTH rejected - session dead, reseat")
    print("-- secure channel open --\n")
    return s_mac, cmac   # session MAC key + first ICV

# ---- secure transmit: EXACT GPPro SCP02Wrapper replication ----
# first command ICV = zeros ("external update ICV MUST be always 0"),
# subsequent ICV = DES-ECB(previous MAC, macKey)   [GPCrypto.des_ecb]
def des1_ecb(k16, b8):
    # single-DES via 3DES with k1=k2=k3 (EDE with equal halves collapses to DES)
    e = Cipher(algorithms.TripleDES(k16[:8]*3), modes.ECB()).encryptor()
    return e.update(b8)+e.finalize()
def des1_cbc(k16, data, iv):
    e = Cipher(algorithms.TripleDES(k16[:8]*3), modes.CBC(iv)).encryptor()
    return e.update(data)+e.finalize()
def mac_des_3des_gpp(key16, data, iv):
    d = pad80(data)
    if len(d) > 8:
        des = des1_cbc(key16, d[:-8], iv)
        iv = des[-8:]
    c = cbc3(key16, d[-8:], iv)
    return c[-8:]

def make_secure_tx(s_mac):
    global s_mac_g, state_g
    s_mac_g = s_mac
    state = {"icv": None}
    state_g = state
    def sx(ins, p1, p2, data=b"", label=""):
        if state["icv"] is None:
            icv = b'\x00'*8
        else:
            icv = des1_ecb(s_mac, state["icv"])
        newlc = len(data) + 8
        mac_input = bytes([0x84, ins, p1, p2, newlc]) + data
        cmac = mac_des_3des_gpp(s_mac, mac_input, icv)
        apdu = [0x84, ins, p1, p2, newlc] + list(data) + list(cmac)
        sw, r = transmit(apdu, label)
        if sw == "9000":
            state["icv"] = cmac
        return sw, r
    return sx, state

def sx_with_le(sx_inner, ins, p1, p2, data, le, label):
    # ... MAC (T=0 case-4)
    global s_mac_g
    if state_g["icv"] is None: icv = b'\x00'*8
    else: icv = des1_ecb(s_mac_g, state_g["icv"])
    newlc = len(data)+8
    mi = bytes([0x84, ins, p1, p2, newlc]) + data
    cmac = mac_des_3des_gpp(s_mac_g, mi, icv)
    apdu = [0x84, ins, p1, p2, newlc] + list(data) + list(cmac) + [le]
    sw, r = transmit(apdu, label)
    if sw == "9000": state_g["icv"] = cmac
    return sw, r

# ---- GET STATUS exactly as GPPro does: sequential P1, data 4F 00, P2=02 (+legacy 00 fallback)
def get_status(sx):
    """Read the registry over the open channel: ISD + apps/SDs + load files.
    Returns (last_sw, concatenated TLV data); empty sections (6A88/6A82) are fine."""
    parts = []
    sw_last = "6A88"
    for p1, kind in [(0x80, "ISD"), (0x40, "apps/SD"), (0x20, "load files")]:
        sw, data = raw_status(sx, p1, 0x02, f"GET STATUS {kind}")
        if sw in ("9000", "6310") and data:
            parts.append(data)
            sw_last = "9000"
        elif sw not in ("6A88", "6A82"):
            sw_last = sw
    return sw_last, b"".join(parts)

def raw_status(sx, p1, p2, label):
    # 84 F2 P1 P2 Lc 4F 00 + C-MAC (P2=0x02: TLV response format)
    return sx(0xF2, p1, p2, bytes([0x4F, 0x00]), label)

def parse_status(data):
    out = []
    i = 0
    while i + 2 <= len(data):
        tag, ln = data[i], data[i+1]
        val = data[i+2:i+2+ln]
        if tag == 0x4F:
            out.append(("app/ISD AID", val.hex().upper()))
        elif tag == 0x9E:
            out.append(("exec load file", val.hex().upper()))
        elif tag == 0xC4 or tag == 0xDB:
            out.append((f"lifecycle/status", val.hex().upper()))
        i += 2 + ln
    return out

# ---- CAP stream ----
def cap_stream(path):
    z = zipfile.ZipFile(path)
    blob = b""
    for comp in COMPONENT_ORDER:
        name = [n for n in z.namelist() if n.endswith(f"/{comp}.cap")]
        if name: blob += z.read(name[0])
    # The J3R150 dialect (transcript 08): the whole stream travels inside
    # one BER-TLV object: C4 <len> ... (the "combined" LOAD form)
    assert len(blob) < 0x10000
    return bytes([0xC4, 0x82, (len(blob) >> 8) & 0xFF, len(blob) & 0xFF]) + blob

# ---- INSTALL for load (P1=02) / LOAD (E8) / INSTALL for install (P1=0C) ----
def install_for_load(sx):
    # The form that worked on the J3R150 (transcript 08):
    # 84 E6 02 00 Lc 07<pkg AID> 08<SD AID> 000000 + C-MAC
    # (the explicit SD AID is required by this firmware; omitting it -> 6A80)
    SD_AID = bytes.fromhex("A000000151000000")
    data = bytes([len(PKG_AID)]) + PKG_AID + bytes([len(SD_AID)]) + SD_AID + b"\x00\x00\x00"
    return sx(0xE6, 0x02, 0x00, data, "INSTALL for load")

def load_blocks(sx, blob):
    # Transcript-08 form: P2 = block counter (00,01,..), P1=80 on the last
    # block only; 247 data bytes + 8 C-MAC = 0xFF per full block.
    total = (len(blob) + 0xF7 - 1) // 0xF7
    for n in range(total):
        chunk = blob[n*0xF7:(n+1)*0xF7]
        last = 0x80 if n == total - 1 else 0x00
        sw, _ = sx(0xE8, last, n, chunk, f"LOAD block {n+1}/{total} ({len(chunk)}B, last={last:02X})")
        if sw != "9000": sys.exit(f"LOAD block {n+1} failed: {sw}")

def install_for_install(sx):
    # Transcript-08 verbatim (31B): pkg AID + applet AID + SD AID + tail.
    # This is the command the firmware answers 6985 to - the instantiation lock.
    data = bytes.fromhex("07F000000001DEAD08F000000001DEAD0108A000000151000000010002C900")
    return sx(0xE6, 0x0C, 0x00, data, "INSTALL for install+selectable")

def delete_package(sx):
    # The form that worked on the J3R150 (transcript 08):
    # 84 E4 00 00 Lc 4F <len> <PKG_AID> 00 <C-MAC>
    data = bytes([0x4F, len(PKG_AID)]) + PKG_AID + b"\x00"
    return sx(0xE4, 0x00, 0x00, data, "DELETE our package")

# ---- stages ----
stage = sys.argv[1] if len(sys.argv) > 1 else "open"

if stage == "setstatus":
    # The form that worked on the J3R150 (transcript 13):
    # SET STATUS P1=0x80 (ISD lifecycle), P2=target -> 9000
    # 0x07 = INITIALIZED (the state INSTALL for load wants), 0x0F = SECURED
    target = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x07
    s_mac, icv0 = open_channel()
    sx, state = make_secure_tx(s_mac)
    state["icv"] = icv0
    sw, _ = sx(0xF0, 0x80, target, b"", f"SET STATUS ISD -> {target:02X}")
    print(f"SET STATUS: {sw}")

elif stage == "open03":
    # Disambiguation probe: C-DECRYPTION-level channel + a NO-DATA command
    # (GET STATUS). If 9000 -> level-03 MAC mechanics fine, 6982 is specific
    # to encrypted-data INSTALL. If 6982 -> level-03 sessions break MAC.
    s_mac, icv0 = open_channel(level=0x03)
    sx, state = make_secure_tx(s_mac)
    state["icv"] = icv0
    sw, resp = sx(0xF2, 0x40, 0x02, b"", "GET STATUS apps (level 03, no data)")
    print(f"GET STATUS under C-DECRYPTION channel: SW {sw}")

elif stage == "install03":
    # Lever: C-MAC + C-DECRYPTION security level (EXTERNAL AUTHENTICATE P1=03)
    # instead of plain C-MAC (0x01). Some firmwares demand encrypted INSTALL
    # bodies. ONE command: INSTALL [for install] with the data field
    # encrypted 3DES-CBC/KDEK (SCP02 wrap: last-8-bytes prefix + rest).
    # Requires the package already in the registry (run load04 first).
    from cryptography.hazmat.primitives.ciphers import Cipher as _C, algorithms as _A, modes as _M
    dek_hex = _os.environ.get("GP_KDEK", _os.environ.get("GP_KENC", _enc))
    KDEK = bytes.fromhex(dek_hex)
    print(f"   DEK = GP_KDEK/GP_KENC default ({dek_hex[:8]}...)")
    s_mac, icv0 = open_channel(level=0x03)
    sx, state = make_secure_tx(s_mac)
    state["icv"] = icv0
    data = bytes.fromhex("07F000000001DEAD08F000000001DEAD0108A000000151000000010002C900")
    pad = data + b"\x80" + b"\x00" * ((8 - len(data) % 8) % 8)
    c = _C(_A.TripleDES(KDEK), _M.CBC(b"\x00" * 8))
    ct = c.encryptor().update(pad)
    wrap = _os.environ.get("GP_WRAP", "last")
    if wrap == "last":    wrapped = ct[-8:] + ct[:-8]
    elif wrap == "first": wrapped = ct[8:] + ct[:8]
    else:                 wrapped = ct
    sw, _ = sx(0xE6, 0x04, 0x00, wrapped, "INSTALL P1=04 (C-DECRYPTION level)")
    print(f"\n>>> INSTALL under C-DECRYPTION: SW {sw}")

elif stage == "load04":
    # Full flow, but with the SPLIT final step: INSTALL [for install] (P1=04)
    # and, only on 9000, INSTALL [for make selectable] (P1=08). Distinguishes
    # "installation itself blocked" from "make-selectable blocked".
    s_mac, icv0 = open_channel()
    sx, state = make_secure_tx(s_mac)
    state["icv"] = icv0
    # NB: a FAILED DELETE (6A88) still advances the card's C-MAC chain on this
    # batch, desyncing the next command (6982). The package is known absent,
    # so skip DELETE; retry the whole session if 6A80 (AID collision) appears.
    sw, _ = install_for_load(sx)
    if sw != "9000": sys.exit("INSTALL for load failed")
    load_blocks(sx, cap_stream(CAP_PATH))
    data = bytes.fromhex("07F000000001DEAD08F000000001DEAD0108A000000151000000010002C900")
    sw, _ = sx(0xE6, 0x04, 0x00, data, "INSTALL [for install] only (P1=04)")
    print(f"\n>>> INSTALL for install: SW {sw}")
    if sw == "9000":
        msdata = bytes.fromhex("08F000000001DEAD01")
        sw2, _ = sx(0xE6, 0x08, 0x00, msdata, "INSTALL [for make selectable] (P1=08)")
        print(f">>> INSTALL make selectable: SW {sw2}")
    else:
        print(">>> make-selectable skipped (install did not pass)")

elif stage == "keyinfo":
    # GET DATA 'Key Information' (tag 00E0) under the secure channel.
    # Reveals whether the ISD carries an RSA/ECC token-verification key
    # (Delegated Management) in addition to the SCP02 DES keyset.
    s_mac, icv0 = open_channel()
    sx, state = make_secure_tx(s_mac)
    state["icv"] = icv0
    sw, resp = sx(0xCA, 0x00, 0xE0, b"", "GET DATA 00E0 (key info)")
    print(f"GET DATA: SW {sw}")
    if resp:
        print("RAW:", resp.hex().upper())
        i = 0
        while i < len(resp):
            if resp[i] == 0xE0:
                ln = resp[i+1]; blob = resp[i+2:i+2+ln]; i += 2 + ln
                j = 0
                while j < len(blob):
                    kid, kvn, ktype, klen = blob[j], blob[j+1], blob[j+2], blob[j+3]
                    types = {0x80:"DES3", 0x88:"AES", 0x81:"RSA_PUBLIC", 0x82:"RSA_PRIVATE", 0x8A:"ECC"}
                    usage = {1:"ENC/MAC/DEK", 2:"ENC", 4:"MAC", 8:"DEK", 0x44:"token+receipt?"}
                    print(f"  key {kid:02X} v{kvn:02X} type={types.get(ktype, hex(ktype))} len={klen}")
                    j += 4 + klen
            else:
                i += 1

elif stage == "install04":
    # Split INSTALL [for install] (P1=0x04) - same 31-byte data field as the
    # combined form. Distinguishes "installation blocked" from
    # "make-selectable blocked".
    s_mac, icv0 = open_channel()
    sx, state = make_secure_tx(s_mac)
    state["icv"] = icv0
    data = bytes.fromhex("07F000000001DEAD08F000000001DEAD0108A000000151000000010002C900")
    sw, _ = sx(0xE6, 0x04, 0x00, data, "INSTALL [for install] only")
    print(f"INSTALL for install: SW {sw}")

elif stage == "lockcheck":
    # One command, the whole story: the INSTALL [for install] form from
    # transcript 08 (byte-for-byte data; the C-MAC is session-fresh).
    # On this card it answers 6985 regardless of ISD lifecycle state -
    # the firmware instantiation lock. No load-file needed (transcript 13).
    s_mac, icv0 = open_channel()
    sx, state = make_secure_tx(s_mac)
    state["icv"] = icv0
    data = bytes.fromhex("07F000000001DEAD08F000000001DEAD0108A000000151000000010002C900")  # transcript-08 verbatim, 31B
    sw, _ = sx(0xE6, 0x0C, 0x00, data, "INSTALL for install+selectable")
    print(f"LOCKCHECK: {sw}  (6985 = firmware instantiation lock)")

elif stage == "delete":
    s_mac, icv0 = open_channel()
    sx, state = make_secure_tx(s_mac)
    state["icv"] = icv0
    sw, _ = delete_package(sx)
    print("DELETE:", sw)

elif stage == "open":
    s_mac, icv0 = open_channel()
    sx, state = make_secure_tx(s_mac)
    for p1, kind in [(0x80, "ISD"), (0x40, "apps/SD"), (0x20, "load files")]:
        for p2 in (0x02, 0x00):
            sw, data = sx_with_le(sx, 0xF2, p1, p2, bytes([0x4F, 0x00]), 0x00, f"GET STATUS {kind} P1={p1:02X} P2={p2:02X}")
            if sw == "9000":
                print(f"   {kind}: {data.hex().upper()[:100]}")
                break
            if sw not in ("6A86", "6A88", "6310"):
                print(f"   {kind}: {sw}")
                break

elif stage == "load":
    s_mac, icv0 = open_channel()
    sx, state = make_secure_tx(s_mac)
    state["icv"] = icv0
    if len(sys.argv) > 2 and sys.argv[2] == "--registry":
        # NB: GET STATUS may answer 6310 (more data); the card advances its
        # C-MAC chain on it while this client does not, so the next MACed
        # command desyncs (6982). Off by default; see docs/quirks.md.
        print("-- registry before --")
        sw, data = get_status(sx)
        for k, v in parse_status(data): print(f"  {k}: {v}")
        print()
    sw, _ = delete_package(sx)
    if sw == "9000":
        print("   old copy deleted")
    elif sw in ("6A88", "6A82"):
        print("   nothing to delete (" + sw + ")")
    else:
        print("   DELETE: " + sw + " (continuing)")
    sw, _ = install_for_load(sx)
    if sw != "9000": sys.exit("INSTALL for load failed")
    load_blocks(sx, cap_stream(CAP_PATH))
    sw, _ = install_for_install(sx)
    if sw != "9000": sys.exit("INSTALL for install failed")
    print("\n-- registry after (install proof) --")
    sw, data = get_status(sx)
    for k, v in parse_status(data): print(f"  {k}: {v}")

elif stage == "perso":
    sw, fci = transmit([0x00, 0xA4, 0x04, 0x00, len(APP_AID)] + list(APP_AID) + [0x00],
                       "SELECT applet")
    if sw != "9000":
        sys.exit(f"applet not selectable (SW {sw}): not instantiated - "
                 "on a locked card this is the 6985 wall from 'load'; "
                 "perso only succeeds after a successful INSTALL for install")
    from cryptography.hazmat.primitives.cmac import CMAC
    from cryptography.hazmat.primitives.ciphers import algorithms as _a
    TK = bytes.fromhex("404142434445464748494A4B4C4D4E4F")
    DK = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    def cmac(key, d):
        c = CMAC(_a.AES(key)); c.update(d); return c.finalize()
    wrap = DK + cmac(TK, DK)
    # 6985 before personalization
    ch = bytes.fromhex("5142434445464748")
    transmit([0x80, 0x32, 0x00, 0x00, len(ch)] + list(ch), "MAC before perso (expect 6985)")
    transmit([0x80, 0x40, 0x00, 0x00, len(wrap)] + list(wrap), "PERSONALIZE (INS 0x40)")
    transmit([0x80, 0x32, 0x00, 0x00, len(ch)] + list(ch), "MAC challenge (INS 0x32)")
    expected = cmac(DK, ch)
    print("expected MAC:", expected.hex().upper())
