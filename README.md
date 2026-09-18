# j3r150-field-kit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A small Java Card bench toolkit: identify a card, open SCP02, load an applet, and verify its MAC. Built during a real hardware session (September 14, 2026) with three cards, two operating systems, and one hand-rolled SCP02 stack.

## What this is

Two J3R150 cards from a marketplace listing that promised "unfused, not initialized". What we can say honestly: the cards carry a custom ISD keyset (printed in the listing) and Visa Token Service load files in the registry, so their history is unknown. Our first reading - "personalized upstream, locked, no stock tool opens them" - was wrong on the lock (see Diagnostics) and overbroad on the stock-tool claim. An independent GPPro v25.10.20 case-4 run still failed on our Mac/reader; that does not establish failure for every tool or identify the faulty layer.

The working setup uses: a hand-rolled SCP02 implementation in plain Python, a minimal installer, and transcripts from the September 2026 hardware sessions.

## Quick start

### 1. Set up the environment (macOS)

```bash
git clone https://github.com/Vitaliy69/j3r150-field-kit
cd j3r150-field-kit
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install cryptography
```

The Python clients use Apple's PCSC.framework through `scripts/pcsc_mac.py`.
They are macOS-specific and do not use pyscard. Installing pyscard does not
port them to Linux or Windows. The independent Java console in
`tools/ApduTest.java` is another transport where a JDK can see the reader.

**Reconnect caveat:** on our Generic EMV reader/macOS setup, a fresh process
can fail to connect after the preceding session closed, even if it only ran
SELECT. Reseat the card before each separate CLI command if you reproduce
`0x80100066`. A held-open connection survived 120 seconds without APDUs;
UNPOWER at disconnect did not fix reconnect. These commands do not share
one connection. See [diagnostics](docs/diagnostics.md) and
[transcript 42](transcripts/42_reviewer_gppro_and_reconnect.txt).

### 2. Identify your card (read-only, safe on any card)

```bash
python3 scripts/card_id.py
```

Expected output:

```
Reader: Generic EMV Smartcard Reader
SCardConnect: 0x0 | proto: T=0
ATR: 3B6A00FF0031C173C84000009000
SELECT ISD                             -> SW 9000
ISD FCI (...)
VERDICT: card answered SELECT; ISD keys were not tested or changed.
```

No keys needed, nothing is written. If you see an ATR and `9000` on SELECT, the hardware works.

### 3. Open a secure channel

```bash
python3 scripts/open_channel.py
```

Expected output:

```
SELECT ISD                             -> SW 9000
INIT UPDATE                            -> SW 9000
EXT AUTH                               -> SW 9000
    SECURE CHANNEL OPEN - manual SCP02 succeeded
```

The working client sends case-3 EXT AUTH. If authentication fails, stop and compare the transcript and documented keyset; see gotcha 5. A failed PC/SC connect is a different error from an APDU status word.

### 4. Run the install pipeline

```bash
python3 scripts/gp_lite.py open       # channel + registry snapshot
python3 scripts/gp_lite.py delete     # clear the slot (own session)
python3 scripts/gp_lite.py full0c     # load + INSTALL + make selectable
python3 scripts/gp_lite.py perso      # personalize + verify one MAC
```

The corrected installation and personalization stages succeeded on the tested
J3R150. An empty DELETE can return `6A88`. Rotation is verified separately in
transcript 41; the four commands above do not run it:

```
INSTALL for load                       -> SW 9000
LOAD 1/4 .. N/N                        -> SW 9000
INSTALL for install (combined)         -> SW 9000
SELECT / PERSONALIZE / MAC             -> SW 9000
```

An earlier revision of this README claimed a firmware-level installation
lock. That claim was wrong: our INSTALL data field put the ISD AID into the
instance-AID slot and omitted the Install Token length - an honest 6985
answer to a malformed question (see Diagnostics).

### Diagnostics: the 6985 that was not a lock

For a week this repository documented a "firmware installation lock": every
LOAD block answered 9000 and INSTALL for install answered 6985 - on three
cards, two keysets, every lifecycle state. An independent review found the
actual cause in one afternoon: our INSTALL data field was malformed.

The GP 2.2.1 INSTALL [for install] data field (Table 11-43):

```
<L> Load File AID        07 F000000001DEAD
<L> Executable Module    08 F000000001DEAD01
<L> Application AID      08 F000000001DEAD01   <- the INSTANCE slot
<L> Privileges           01 00                  <- LV-encoded, canonical
<L> Install parameters   02 C9 00
<L> Install Token        00                     <- empty length must be present
```

Our historical form put the ISD AID (A000000151000000) into the instance
slot and omitted the token length: an AID conflict and a short field,
answered with a legitimate 6985. Standard corrected form -> 9000.

What survived the review:
- SCP02 opens with the documented batch keys; the working client uses
  encrypted ICV chaining after EXT AUTH.
- The two tested card/tool combinations accepted different LOAD boundaries.
- One-shot personalization, domain separation and rotation passed on hardware.

What remains uncertain: reader/card/driver attribution of the reconnect
failure, exact firmware/fuse state, and the meaning of repeated challenges
in historical failed handshakes. The earlier claim that `i=02` mandated
ICV encryption was wrong; GP's ICV-encryption option is bit `0x10`.

What fell (our errors, fixed):
- "26-byte truncated responses" - a GET RESPONSE assembly bug in transmit()
  (fixed; the reviewer's mock test passes, including the 6C-then-61 edge)
- "SELECT hangs the card" - ctypes binding defects: 16-byte SCARD_IO_REQUEST
  where the SDK defines 8 (native saw cbPciLength=0), an 8th argument in
  SCardTransmit, unchecked rc (all fixed; javax.smartcardio selects fine)
- "the batch does not permit installation" - the malformed INSTALL above
  (transcript 38: corrected form -> 9000; 39: full lifecycle on hardware;
  41: hardware key rotation with domain separation)

Method lesson (now gotcha 18): a status-word wall is only a wall after the
command encoding is verified against the spec tables - characterizing the
card's answers (keys, tokens, lifecycle, security levels) does not rule out
the simplest cause: your own bytes.

### 5. Your own card's keys

Channel-opening clients default to our documented batch keyset. `gp_lite.py` accepts `GP_KEYSET`, `GP_KENC`, and `GP_KMAC`; the earlier invalid `install03` wrapping probe is archived. `GP_INSTANCE` selects the application instance AID while the module AID remains the one compiled into the CAP. `card_id.py` needs no keys.

## One key's whole life, in one script

The full device-key lifecycle - personalize, authenticate, rotate, revoke - as a single
runnable demo, no card required:

    /usr/bin/python3 examples/collar_lifecycle.py

The card side is a stub that computes byte-for-byte what the applet computes; on hardware,
`CardStub.mac()` becomes the PC/SC exchange in `scripts/`. The last two lines of the output
are the lesson: after revocation the card still MACs fine - it is healthy, just orphaned -
because revocation is a fact the backend knows and the card never learns.

`docs/lifecycle.md` maps each stage onto the real transcripts in this repository and
links the canonical applet source.

## Where to get a card

- **Works:** developer parts with documented ISD keys - chipmaker dev kits, distributor sample cards. You get the keyset in the documentation (often the factory test key `4041...4E4F`) and an unlocked ISD.
- **Lottery:** marketplace "blank unfused" listings. Some are genuine dev stock; the card's prior history may be unknown. Before blaming the card for a "lock", verify your own command encodings against the spec tables - our week-long "firmware install lock" was our own malformed INSTALL (see Diagnostics). If the listing cannot answer "what are the ISD keys (hex) and which Java Card version?" - assume you will need patience.
- **If you already have a PI260905-2133 batch card:** the keys below open the channel and the FULL cycle works - load, install, personalize, MAC, rotate (transcripts 38-41; use the standard INSTALL form from Diagnostics).

## Repository structure

```
scripts/
  pcsc_mac.py         - shared Apple PC/SC transport and continuation handling
  card_id.py          - read-only identification (ATR, ISD presence)
  open_channel.py     - manual SCP02 handshake (case-3 EXT AUTH)
  gp_lite.py          - minimal installer pipeline (DELETE old copy, INSTALL for load, LOAD, INSTALL)
                        stages: open | delete | setstatus <hex> | load [--registry] | perso
                        (setstatus: ISD lifecycle P1=0x80 form from transcript 13; 07=INITIALIZED)
  probe_extauth.py    - archived dummy-cryptogram probe; sends no APDUs

applet/
  CollarMAC.java      - the applet (Java Card 3.0.5, ALG_AES_CMAC_128)
  CollarMAC222.java   - the applet (Java Card 2.2.2, ALG_AES_MAC_128_NOPAD)

examples/
  collar_lifecycle.py - the full key lifecycle demo (personalize, authenticate,
                       rotate, revoke; no card needed)

docs/
  keys.md             - the batch keyset and how it was verified
  quirks.md           - observations, corrections and remaining uncertainties
  lifecycle.md        - device-key lifecycle, evidence and demo limits

transcripts/           - complete console output from every session (indexed below)
```

## Troubleshooting: the status-word matrix

Every failure mode we hit, in one table. Column "Gotcha" refers to the numbered gotchas above.

| Status word | What the card is saying | Your move | Gotcha |
|---|---|---|---|
| `9000` | Success | Continue | - |
| `61xx` | More data waiting (xx bytes) | Send GET RESPONSE | 14 |
| `6Cxx` | Wrong Le; resend with this length | Resend with Le=xx | 14 |
| `63Cx` | Auth failed; x tries left | STOP. Check keys, never brute-force | try counter |
| `644F` | Memory error during LOAD | Stream too big or wrong format - compare the exact CAP stream and block boundaries | 3, 9 |
| `6982` | Security status not satisfied | MAC/ICV chain wrong - check ICV encryption | 6 |
| `6985` | Conditions not satisfied | On INSTALL: check your data field against the spec tables first (AID slots, token length) - ours was malformed (see Diagnostics). On MAC/ROTATE before personalization or with a wrong-domain tag: by design | 16, 38, 41 |
| `6A80` | Bad parameters in command data | Dialect mismatch - try the other INSTALL/LOAD form | 7, 8, 9 |
| `6A82` | Applet/file not found | Wrong AID - package AID vs applet AID (last byte) | - |
| `6A86` | P1/P2 invalid | PUT KEY needs P2=0x81 | 11 |
| `6A88` | Referenced data not found | DELETE on an empty registry - nothing there | - |
| `6D00` | Instruction not supported | EXT AUTH case-4 rejected - send case-3 | 5 |

If a card stops answering entirely (`SCARD_W_UNRESPONSIVE_CARD`): pull it from the reader; if that fails, unplug the reader's USB (the reader holds state too - gotcha 14). If it stays dead, the card is gone - worn out, aged out, or otherwise finished (gotcha 13/17); see the article for why our ~20 cycles alone could not kill healthy 100K-rated EEPROM.

## Transcript index

Numbered in rough story order: J3R150 sessions (01-14), Mikron sessions (15-33).

| File | What happened |
|---|---|
| `01_build_cap_jc305.txt` | CAP built: JDK 17 `--release 7`, converter 3.0.5, zero errors |
| `02_j3r150_registry_getstatus.txt` | Card registry read: Visa load files, NFC Forum applet, SSD |
| `03_j3r150_manual_scp02_success.txt` | First fully manual SCP02 handshake (the article's Step 2) |
| `04_j3r150_putkey_batch_to_factory.txt` | PUT KEY: batch keyset replaced with factory 40..4F, KCV x3 |
| `05_j3r150_install_6a80.txt` | INSTALL for install: 6A80 (wrong dialect) |
| `06_j3r150_install_gppro_form_6a80.txt` | GPPro-minimal install form: still 6A80 |
| `07_j3r150_after_putkey_install_6a80.txt` | After PUT KEY: install still fails - lock is not key-based |
| `08_j3r150_load_success_install_locked.txt` | THE session: LOAD 4/4 = 9000, install = 6985 |
| `09_j3r150_jc222_cap_split_load.txt` | JC 2.2.2 CAP, split LOAD dialect on J3R150 |
| `10_j3r150_jc222_cap_combined_load.txt` | JC 2.2.2 CAP, combined dialect |
| `11_j3r150_cmac_verify_session.txt` | CMAC verification session |
| `12_j3r150_card2_batch_lock_confirmed.txt` | Second card, same batch: lock is innate |
| `13_j3r150_setstatus_lifecycle_matrix.txt` | SET STATUS: OP_READY -> INITIALIZED -> SECURED walk |
| `34_keyinfo_three_des_only.txt` | GET DATA 00E0: ISD carries ONLY the three SCP02 3DES keys - no token-verification key exists |
| `35_split_install_04_6985.txt` | Split INSTALL: P1=04 alone -> 6985 (block is on installation, not make-selectable) |
| `36_card1_factory_keyset_lock.txt` | Same 6985 under a different keyset (factory v02); SET STATUS -> SECURED itself refused |
| `37_cdecryption_level_probe.txt` | Reconstructed summary (raw log lost before first commit): C-DECRYPTION level reportedly accepted; INSTALL 6982 with invalid static-DEK wrapping; inconclusive probe |
| `38_phantom_lock_install_succeeds.txt` | THE PIVOT: corrected standard INSTALL form -> 9000; full GP cycle; CAP SHA-256; the "lock" was our malformed data field |
| `39_full_lifecycle_on_hardware.txt` | Full lifecycle on hardware via javax.smartcardio: perso, MAC byte-for-byte, one-shot rule |
| `40_rotate_domain_separation_harness.txt` | jCardSim 18/18 after domain separation: forgery rejected, stale-engine fixed, boundary lengths |
| `41_hardware_rotation_domain_separated.txt` | Hardware key rotation: forgery 6982, stale-engine recovery, K1->K2, persistence, replay rejected |
| `42_reviewer_gppro_and_reconnect.txt` | Independent cross-check, curated excerpts: GlobalPlatformPro EXT AUTH 6D00 (case-4) over javax.smartcardio; reader-reconnect LEAVE/HOLD/UNPOWER probes all end 0x80100066; attribution left open |
| `14_hypotheses_log.txt` | The hypotheses ledger: what we tried and ruled out |
| `15_mikron_first_probe.txt` | First contact with the Mikron (proto negotiation) |
| `16_mikron_probe_raw_reader.txt` | Raw-reader probe |
| `17_mikron_baseline_clean.txt` | Mikron baseline: clean session, factory keys |
| `18_mikron_channel_open.txt` | SCP02 channel open on Mikron |
| `19_mikron_load_combined_rejected.txt` | Combined LOAD on Mikron: 644F - dialect rejection |
| `20_mikron_delete_dialect_tests.txt` | DELETE parameter dialects: 6A80/6A82 experiments |
| `21_mikron_single_block_load_6a80.txt` | Single-block LOAD attempt: 6A80 |
| `22_mikron_tlv_length_tests.txt` | BER-TLV length encoding tests (81 xx vs raw) |
| `23_mikron_descriptor_stream_test.txt` | LOAD stream with Descriptor included: memory error |
| `24_mikron_load_after_cleanup_644f.txt` | LOAD after registry cleanup: still 644F |
| `25_mikron_load_split_format_644f.txt` | Split format attempt: header ok, data blocks 644F |
| `26_mikron_final_session_card_failing.txt` | Card visibly failing (responses degrading) |
| `27_mikron_load_header_block_accepted.txt` | Split header block accepted (9000), data blocks 644F |
| `28_mikron_case4_extauth_test.txt` | Case-4 EXT AUTH on Mikron: accepted (unlike J3R150) |
| `29_mikron_icv_variants.txt` | ICV derivation variants tested against the card |
| `30_mikron_protocol_t0_t1_test.txt` | T=1 rejected / T=0 negotiation tests |
| `31_mikron_recovery_after_wedge.txt` | Recovery after a wedged session (reseat + USB unplug) |
| `32_mikron_run4_full_attempt.txt` | RUN-4: full install attempt via the card_id stack |
| `33_mikron_run4_final_card_dying.txt` | Final session: card returning zeros - unresponsive for good |

## The batch keyset

Public record ([GlobalPlatformPro discussion #382](https://github.com/martinpaljak/GlobalPlatformPro/discussions/382) and marketplace reviews), verified against the card's own cryptogram:

```
ENC 90379A3E7116D455E55F9398736A01CA
MAC 473F36161A7F7F60CC3A766EA4BE5247
DEK D3749ED4FF42FD58B39EEB562B017CD9
```

These are transport keys in the public domain - the printed front-door key genre the JCOP21 line made famous, not a payment secret.

## The 18 gotchas

| # | Gotcha | Fix |
|---|---|---|
| 1 | Converter rejects class > v51 (JC 3.0.5) / > v48 (JC 2.2.2) | `--release 7` or patch class major to 48 |
| 2 | Converter requires real Java package | Wrap applet in `package xxx;` |
| 3 | CAP component selection must match the tested stream | Current kit includes Descriptor; preserve the tested component order |
| 4 | Client stripped two payload bytes during GET RESPONSE | Assemble once; require 28 bytes and verify the cryptogram |
| 5 | EXT AUTH case-4 rejected (6D00) | Send case-3 (no Le) |
| 6 | ICV chain starts at EXT AUTH | First command ICV = DES-ECB(EXT_AUTH_MAC) |
| 7 | Empty INSTALL-for-load values still need lengths | Five standard fields, ending with Load Token length |
| 8 | BER-TLV length: 128-255 needs `81 xx`, 256+ needs `82 xx xx` | Use correct encoding |
| 9 | LOAD has 2 dialects (combined vs split blocks) | Try both |
| 10 | The INSTALL "dialects" were one spec form misread: instance AID is the standard third slot; the "SD-as-third" variant was our bug | Build from Table 11-43 (LF, module, instance, LV-priv, params, token len) |
| 11 | PUT KEY: P2=0x81, no per-key ID bytes, keys encrypted with S-DEK | Follow exact encoding |
| 12 | ALG_AES_CMAC_128 (CMAC) is JC 3.0.5+; ALG_AES_MAC_128_NOPAD (CBC-MAC) is JC 2.2.2 - different constructions, NOT equivalent | Use matching SDK + host-side algorithm |
| 13 | EEPROM has finite write cycles | Don't loop install/delete unnecessarily |
| 14 | Reconnect can fail after a successful SELECT-only session | Reseat between CLI sessions on affected setups; cause unresolved |
| 15 | GET STATUS P1 format varies (combined vs sequential) | Try P1=80/40/20 sequentially with P2=02 |
| 16 | Different LOAD block boundaries worked in the recorded setups | Preserve the exact trace and test environment |
| 17 | Used dev cards arrive with unknown remaining write cycles (rated ~100K/cell, but history is invisible) | Treat used cards as consumables |
| 18 | A `6985` wall may live in your own command bytes: verify the data field against the spec tables (AID slots, LV privileges, token length) before blaming the card - our 'firmware lock' was exactly this | transcript 38 (corrected form -> 9000) |

## Key discoveries

### The case-3 EXT AUTH bug

GPPro v25.10.20 through javax.smartcardio on macOS 26.7, Generic EMV reader,
T=0: case-4 EXT AUTH returned `6D00`. Our case-3 sessions succeeded. This
independent run confirms the observed failure without the old Python binding;
other versions, readers, protocols and the rejecting layer remain untested.
See [transcript 42](transcripts/42_reviewer_gppro_and_reconnect.txt).

### The ICV chain

The comment in GlobalPlatformPro's SCP02Wrapper.java says "ICV MUST be always 0". This is misleading: EXT AUTH is the first command wrapped by the secure channel, so its MAC becomes the ICV for the second command. The correct chain is:

```
ICV(command_1) = DES-ECB(MAC_of_EXT_AUTH)
ICV(command_n) = DES-ECB(MAC_of_command_{n-1})
```

### Two LOAD dialects

| Format | Description | Works on |
|---|---|---|
| Combined | TLV header + data in same block (~247B/block) | NXP J3R150 |
| Split | Block 1 = TLV header only (4B), blocks 2+ = data (~220B/block) | Mikron IoT |

These are the accepted layouts in the recorded sessions. The cross-tests failed,
but they do not establish a universal vendor split or isolate firmware from
reader, protocol and tooling differences.

## What worked and what didn't

| Card | LOAD | INSTALL | Notes |
|---|---|---|---|
| J3R150 #1 (used) | Combined format OK | 6985 (old form) | Not re-verified with the corrected form; result inferred from #3 |
| J3R150 #2 (fresh) | Combined format OK | 6985 (old form) | Not re-verified with the corrected form; result inferred from #3 |
| J3R150 #3 | Combined format OK | 9000 | Full cycle incl. rotation, verified on hardware (transcripts 38-41) |
| Mikron (2019 dev card) | Split format OK (Windows/smacon) | OK (Windows/smacon) | SELECT and pre-personalization response verified; later became unresponsive, cause unknown |

## Requirements

- macOS with PCSC for these Python clients
- Python 3 with the `cryptography` package
- Any CCID smartcard reader
- Java Card SDK 3.0.5 or 2.2.2 (for building the CAP)

## Building the CAP

```bash
# Java Card 3.0.5
# JDK 21 refuses --release 7; compile --release 8 and patch the class
# major-version byte (offset 7) from 52 to 51 - the JC 3.0.5 converter limit.
# CLEAN THE CLASS DIR FIRST: the converter packs every class it finds in the
# package - a stale extra .class silently rides along into the CAP.
rm -rf build/collarmac && mkdir -p build
javac --release 8 -classpath sdk/jc305u2/lib/api_classic.jar -d build sim/CollarMACRotate.java
python3 -c "d=bytearray(open('build/collarmac/CollarMACRotate.class','rb').read()); d[7]=51; open('build/collarmac/CollarMACRotate.class','wb').write(bytes(d))"
java -cp sdk/jc305u2/lib/tools.jar \
  com.sun.javacard.converter.Main -config CollarMACRotate.opt

# The older CBC-MAC example is a separate protocol, not a drop-in CMAC build.
# Use the JC 2.2.2 toolchain only when targeting that example.
```

## License

MIT - same as the tutorial series. The applet code is yours to use, modify, and ship.

## Credit

The reverse-engineering path leaned on GlobalPlatformPro's open source (especially SCP02Wrapper.java and GPCrypto.java), the vendor's own Smacon tool logs from 2019, and independent review against the specification tables.

Use the established tools when they work for your setup. This kit makes the command bytes and the experiments easy to inspect.

## Verification without a card

```bash
python3 -m unittest discover -s tests
python3 -O -m unittest discover -s tests
python3 examples/collar_lifecycle.py
```

These tests mock the transport and exercise lifecycle/encoding behavior.
They do not establish hardware stability. `sim/HarnessRotate.java` checks the
canonical Java applet in jCardSim. Historical sources in `applet/` use an older
MAC protocol; the build above uses `sim/CollarMACRotate.java`.
