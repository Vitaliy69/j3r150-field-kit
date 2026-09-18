#!/usr/bin/env python3
"""gp-lite: a small GlobalPlatform installer for the
J3R150 bench. Stage `open`  = SCP02 handshake + GET STATUS (registry listing).
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
APP_AID_BYTES = bytes.fromhex("F000000001DEAD01")  # module AID in the CAP
APP_AID  = bytes.fromhex(_os.environ.get("GP_INSTANCE", "F000000001DEAD01"))  # единый источник: SELECT и instance
CAP_PATH = "build/cap/collarmac/javacard/collarmac.cap"
BLOCK    = 0xC0
COMPONENT_ORDER = ["Header", "Directory", "Applet", "Import", "ConstantPool",
                   "Class", "Method", "StaticField", "RefLocation", "Export", "Descriptor"]

# All three clients share the Apple ABI and APDU continuation handling.
from pcsc_mac import CardConnection
if len(sys.argv) > 1 and sys.argv[1] in ("install03", "installfix"):
    sys.exit("Historical probe archived; see transcripts. Use full0c for installation.")
card_connection = CardConnection()
raw = card_connection.raw
transmit = card_connection.transmit

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
        sw, resp = transmit(apdu, f"INITIALIZE UPDATE #{attempt+1}",
                            has_le=bool(attempt % 2))
        if sw == "9000": break
    else: sys.exit("INIT UPDATE failed 8 times - reseat")
    if len(resp) != 28:
        sys.exit(f"INIT UPDATE: expected 28 bytes, got {len(resp)} - transport broken")
    x2 = resp[12:14]; cc = resp[12:20]
    s_enc = derive(KENC, 0x82, x2); s_mac = derive(KMAC, 0x01, x2)
    card_crypto = mac_3des(s_enc, hc + cc)
    if card_crypto != resp[20:28]:
        sys.exit("card cryptogram mismatch - wrong keys or corrupted exchange")
    host_crypto = mac_3des(s_enc, cc + hc)
    mac_input = bytes([0x84, 0x82, level, 0x00, 0x10]) + host_crypto
    cmac = mac_des_3des(s_mac, mac_input)
    ext = [0x84, 0x82, level, 0x00, 0x10] + list(host_crypto) + list(cmac)
    lbl = "EXTERNAL AUTHENTICATE (C-MAC+C-DECRYPT)" if level == 0x03 else "EXTERNAL AUTHENTICATE (C-MAC level)"
    sw, _ = transmit(ext, lbl, has_le=False)
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

# NB: MACed commands built by sx() are case-3 (no Le). transmit() treats a
# 6Cxx on them by APPENDING the hinted Le instead of overwriting the last
# data byte - see the has_le parameter below.
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
        sw, r = transmit(apdu, label, has_le=False)
        if sw in ("9000", "6310"):
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
    sw, r = transmit(apdu, label, has_le=True)
    if sw in ("9000", "6310"): state_g["icv"] = cmac
    return sw, r

# ---- GET STATUS exactly as GPPro does: sequential P1, data 4F 00, P2=02 (+legacy 00 fallback)
def get_status(sx):
    """Collect each registry section, including 6310 continuation pages."""
    parts = []
    sw_last = "6A88"
    for p1, kind in [(0x80, "ISD"), (0x40, "apps/SD"), (0x20, "load files")]:
        for page in range(64):
            sw, data = raw_status(sx, p1, 0x02 if page == 0 else 0x03,
                                  f"GET STATUS {kind} page {page + 1}")
            if sw in ("9000", "6310"):
                parts.append(data)
                sw_last = "9000"
                if sw == "6310":
                    continue
            elif sw not in ("6A88", "6A82"):
                return sw, b"".join(parts)
            break
        else:
            raise RuntimeError("GET STATUS continuation limit reached")
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


def make_selectable_data(instance=None):
    """GP 2.2.1 Table 11-44: two empty slots, instance, privileges, params, token."""
    if instance is None:
        instance = APP_AID
    if not 5 <= len(instance) <= 16:
        raise ValueError("Instance AID must contain 5..16 bytes")
    return b"\x00\x00" + bytes([len(instance)]) + instance + b"\x01\x00\x00\x00"

def load_blocks(sx, blob):
    # Transcript-08 form: P2 = block counter (00,01,..), P1=80 on the last
    # block only; 247 data bytes + 8 C-MAC = 0xFF per full block.
    total = (len(blob) + 0xF7 - 1) // 0xF7
    for n in range(total):
        chunk = blob[n*0xF7:(n+1)*0xF7]
        last = 0x80 if n == total - 1 else 0x00
        sw, _ = sx(0xE8, last, n, chunk, f"LOAD block {n+1}/{total} ({len(chunk)}B, last={last:02X})")
        if sw != "9000": sys.exit(f"LOAD block {n+1} failed: {sw}")

def standard_install_data(instance=None):
    """The one canonical GP 2.2.1 INSTALL [for install] data field (Table
    11-43): LF AID, module AID, INSTANCE AID, LV privileges, LV parameters,
    install token length. Every stage uses THIS encoder - the historical
    31-byte form (ISD AID in the instance slot, token length missing) is what
    we once mistook for a firmware lock. The instance defaults to APP_AID,
    which follows GP_INSTANCE - one source for INSTALL and SELECT."""
    if instance is None:
        instance = APP_AID
    return (bytes([len(PKG_AID)]) + PKG_AID
            + bytes([len(APP_AID_BYTES)]) + APP_AID_BYTES
            + bytes([len(instance)]) + instance
            + bytes([0x01, 0x00, 0x02]) + b"\xC9\x00" + bytes([0x00]))

def install_for_install(sx):
    # Standard GP 2.2.1 form (Table 11-43): LF AID, module AID, INSTANCE AID,
    # LV privileges, LV install parameters, install token length. The historical
    # form put the ISD AID into the instance slot and omitted the token length -
    # an honest 6985 (AID conflict) that we once called a firmware lock.
    return sx(0xE6, 0x0C, 0x00, standard_install_data(),
              "INSTALL for install+selectable (standard form)")

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

elif stage == "full0c":
    # The full working pipeline in the card's real dialect:
    # INSTALL for load -> LOAD blocks -> combined INSTALL (standard LV privileges).
    # Registry must be clean of the package beforehand.
    s_mac, icv0 = open_channel()
    sx, state = make_secure_tx(s_mac)
    state["icv"] = icv0
    sw, _ = install_for_load(sx)
    if sw != "9000": sys.exit("INSTALL for load failed")
    load_blocks(sx, cap_stream(CAP_PATH))
    inst = APP_AID   # тот же единый источник
    data = standard_install_data(inst)
    sw, _ = sx(0xE6, 0x0C, 0x00, data, f"INSTALL combined (standard form, inst={inst.hex().upper()})")
    print(f">>> combined: {sw}")
    if sw == "9000":
        print("*** INSTALLED AND SELECTABLE ***")
    else:
        sys.exit(f"INSTALL failed: {sw} - verify the form (see Diagnostics)")

elif stage == "delinst":
    # DELETE a single application instance by AID (instances must go before
    # the load file): 84 E4 00 00 4F <len> <AID> 00
    target = sys.argv[2]
    s_mac, icv0 = open_channel()
    sx, state = make_secure_tx(s_mac)
    state["icv"] = icv0
    aid = bytes.fromhex(target)
    data = bytes([0x4F, len(aid)]) + aid + b"\x00"
    sw, _ = sx(0xE4, 0x00, 0x00, data, f"DELETE instance {target}")
    print(f">>> {sw}")

elif stage == "install0c":
    # Combined INSTALL (install + make selectable) in the dialect this card
    # accepts (LV privileges + real instance AID + trailing token length).
    # Expects the package in the registry and no live instance yet.
    s_mac, icv0 = open_channel()
    sx, state = make_secure_tx(s_mac)
    state["icv"] = icv0
    data = standard_install_data()
    sw, _ = sx(0xE6, 0x0C, 0x00, data, "INSTALL combined (standard LV privileges)")
    print(f">>> combined: {sw}")
    if sw == "9000":
        print("*** INSTALLED AND SELECTABLE ***")

elif stage == "makesel":
    # INSTALL [for make selectable] P1=08 - the step the "lock" story never reached
    target = sys.argv[2] if len(sys.argv) > 2 else APP_AID.hex()
    s_mac, icv0 = open_channel()
    sx, state = make_secure_tx(s_mac)
    state["icv"] = icv0
    aid = bytes.fromhex(target)
    data = make_selectable_data(aid)
    sw, _ = sx(0xE6, 0x08, 0x00, data, f"INSTALL [make selectable] {target}")
    print(f">>> make selectable: {sw}")

elif stage == "installfix":
    # ARCHIVED (historical): the A-D form sweep that located the phantom
    # lock (transcript 38). The live encoder is full0c / standard_install_data().
    print("[archived stage - see transcripts/38; use full0c]")

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
    sys.exit("install03 is archived: its static-DEK wrapping was not valid SCP02 C-DECRYPTION; use full0c")

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
    data = standard_install_data()
    sw, _ = sx(0xE6, 0x04, 0x00, data, "INSTALL [for install] only (P1=04)")
    print(f"\n>>> INSTALL for install: SW {sw}")
    if sw == "9000":
        msdata = make_selectable_data()
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
    # Split INSTALL [for install] (P1=0x04) - same standard data field as the
    # combined form. Distinguishes "installation blocked" from
    # "make-selectable blocked".
    s_mac, icv0 = open_channel()
    sx, state = make_secure_tx(s_mac)
    state["icv"] = icv0
    data = standard_install_data()
    sw, _ = sx(0xE6, 0x04, 0x00, data, "INSTALL [for install] only")
    print(f"INSTALL for install: SW {sw}")

elif stage == "lockcheck":
    # One command, the whole story: the STANDARD INSTALL form. On this card
    # it answers 9000 (install succeeds; see transcripts 38-41). A 6985 here
    # means: verify the form before blaming the card (see Diagnostics).
    s_mac, icv0 = open_channel()
    sx, state = make_secure_tx(s_mac)
    state["icv"] = icv0
    sw, _ = sx(0xE6, 0x0C, 0x00, standard_install_data(),
               "INSTALL (standard form; package must already be loaded)")
    print(f"LOCKCHECK: {sw}  (9000 = installs; 6985 = check the form, see Diagnostics)")

elif stage == "delete":
    s_mac, icv0 = open_channel()
    sx, state = make_secure_tx(s_mac)
    state["icv"] = icv0
    sw, _ = delete_package(sx)
    print("DELETE:", sw)

elif stage == "open":
    s_mac, icv0 = open_channel()
    sx, state = make_secure_tx(s_mac)
    state["icv"] = icv0
    sw, data = get_status(sx)
    print("REGISTRY:", data.hex().upper())
    if sw not in ("9000", "6A88", "6A82"):
        sys.exit(f"GET STATUS failed: {sw}")

elif stage == "load":
    s_mac, icv0 = open_channel()
    sx, state = make_secure_tx(s_mac)
    state["icv"] = icv0
    if len(sys.argv) > 2 and sys.argv[2] == "--registry":
        # Registry pages use the same secure-channel chain as later commands.
        print("-- registry before --")
        sw, data = get_status(sx)
        if sw not in ("9000", "6A88", "6A82"):
            sys.exit(f"GET STATUS failed: {sw}")
        print(data.hex().upper())
    sw, _ = delete_package(sx)
    if sw == "9000":
        print("   old copy deleted")
    elif sw in ("6A88", "6A82"):
        sys.exit(f"DELETE returned {sw}; restart with full0c in a fresh session")
    else:
        sys.exit(f"DELETE failed: {sw}")
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
    transmit([0x80, 0x32, 0x00, 0x00, len(ch)] + list(ch),
             "MAC before perso (expect 6985)", has_le=False)
    sw_p, _ = transmit([0x80, 0x40, 0x00, 0x00, len(wrap)] + list(wrap),
                       "PERSONALIZE (INS 0x40)", has_le=False)
    if sw_p != "9000":
        sys.exit(f"PERSONALIZE failed: {sw_p} (6985 = already personalized - one-shot)")
    sw, resp = transmit([0x80, 0x32, 0x00, 0x00, len(ch)] + list(ch),
                        "MAC challenge (INS 0x32)", has_le=False)
    expected = cmac(DK, bytes([0x01]) + ch)   # domain-separated applet (CTX_MAC)
    print("expected MAC:", expected.hex().upper())
    got = resp.hex().upper()
    print("card    MAC:", got)
    if sw != "9000" or got != expected.hex().upper():
        sys.exit("PERSO VERIFICATION FAILED - card MAC does not match host")
    print("VERIFIED: card MAC == host MAC")
