# j3r150-field-kit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A toolkit for putting JavaCard applets onto smart cards that reject every standard tool. Built during a real hardware session (September 14, 2026) with three cards, two operating systems, and one hand-rolled SCP02 stack.

## What this is

Two J3R150 cards from a marketplace listing that promised "unfused, not initialized". In reality the batch had been personalized upstream for a Visa payment pipeline, and the cards carry a custom ISD keyset plus an undocumented LOAD format preference. No stock tool opens them.

This kit is what opened them anyway: a hand-rolled SCP02 implementation in plain Python, a minimal installer, and every transcript from the September 14, 2026 hardware sessions.

## Quick start

### 1. Set up the environment (macOS)

```bash
brew install swig                     # pyscard build dependency
pip3 install pyscard cryptography     # reader access + host-side crypto
git clone https://github.com/Vitaliy69/j3r150-field-kit
cd j3r150-field-kit
```

Linux: `sudo apt install pcscd pcsc-tools swig` covers the stack, then the same `pip3` line.
Windows: install [Python](https://python.org) and [Git](https://git-scm.com), plug in the reader (drivers ship with Windows), then the same `pip3 install pyscard cryptography`.

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
...registry entries (load files, applets)...
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
    SECURE CHANNEL OPEN (SCP02, i=02)
```

Stops at `6D00` on EXT AUTH? Your card wants the case-4 form - see gotcha 5 and `scripts/probe_extauth.py`.

### 4. Run the install pipeline

```bash
python3 scripts/gp_lite.py
```

On an unlocked card every stage answers `9000`. On the locked J3R150 batch:

```
INSTALL for load                       -> SW 9000
LOAD 1/4                               -> SW 9000
LOAD 2/4 .. 4/4                        -> SW 9000
INSTALL for install                    -> SW 6985   <-- firmware lock (see "What worked")
```

### 5. Your own card's keys

The scripts carry our batch keyset at the top of each file (`KENC`, `KMAC`, `KDEK`). If your card came with different keys, replace the three hex strings - those three lines are the only card-specific code in the toolkit.

## One key's whole life, in one script

The full device-key lifecycle - personalize, authenticate, rotate, revoke - as a single
runnable demo, no card required:

    /usr/bin/python3 examples/collar_lifecycle.py

The card side is a stub that computes byte-for-byte what the applet computes; on hardware,
`CardStub.mac()` becomes the PC/SC exchange in `scripts/`. The last two lines of the output
are the lesson: after revocation the card still MACs fine - it is healthy, just orphaned -
because revocation is a fact the backend knows and the card never learns.

`docs/lifecycle.md` maps each stage onto the real transcripts in this repository and
carries the applet-side INS_ROTATE (0x42) rotation delta.

## Where to get a card

- **Works:** developer parts with documented ISD keys - chipmaker dev kits, distributor sample cards. You get the keyset in the documentation (often the factory test key `4041...4E4F`) and an unlocked ISD.
- **Lottery:** marketplace "blank unfused" listings. Some are genuine dev stock; many are payment-batch escapees with a firmware-level install lock. If the listing cannot answer "what are the ISD keys (hex) and which Java Card version?" - assume the worst.
- **If you already have a PI260905-2133 batch card:** the keys below open the channel, LOAD works, and the install lock greets you at the end. Everything up to that point is reproducible with this kit.

## Repository structure

```
scripts/
  card_id.py          - read-only identification (ATR, ISD presence)
  open_channel.py     - manual SCP02 handshake (case-3 EXT AUTH)
  gp_lite.py          - minimal installer pipeline (DELETE old copy, INSTALL for load, LOAD, INSTALL)
                        stages: open | delete | setstatus <hex> | load [--registry] | perso
                        (setstatus: ISD lifecycle P1=0x80 form from transcript 13; 07=INITIALIZED)
  probe_extauth.py    - the format probe that isolated the case-3/case-4 bug

applet/
  CollarMAC.java      - the applet (Java Card 3.0.5, ALG_AES_CMAC_128)
  CollarMAC222.java   - the applet (Java Card 2.2.2, ALG_AES_MAC_128_NOPAD)

examples/
  collar_lifecycle.py - the full key lifecycle demo (personalize, authenticate,
                       rotate, revoke; no card needed)

docs/
  keys.md             - the batch keyset and how it was verified
  quirks.md           - firmware misbehavior catalog (17 items)
  lifecycle.md        - the key lifecycle mapped onto real transcripts + INS_ROTATE delta

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
| `644F` | Memory error during LOAD | Stream too big or wrong format - check Descriptor exclusion and dialect | 3, 9 |
| `6982` | Security status not satisfied | MAC/ICV chain wrong - check ICV encryption | 6 |
| `6985` | Conditions not satisfied | On INSTALL: firmware lock (unfixable). On MAC before personalization: by design | 16 |
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

## The 17 gotchas

| # | Gotcha | Fix |
|---|---|---|
| 1 | Converter rejects class > v51 (JC 3.0.5) / > v48 (JC 2.2.2) | `--release 7` or patch class major to 48 |
| 2 | Converter requires real Java package | Wrap applet in `package xxx;` |
| 3 | Descriptor.cap not sent to card | Exclude from LOAD stream |
| 4 | INIT UPDATE response truncated | Retry with/without trailing Le |
| 5 | EXT AUTH case-4 rejected (6D00) | Send case-3 (no Le) |
| 6 | ICV chain starts at EXT AUTH | First command ICV = DES-ECB(EXT_AUTH_MAC) |
| 7 | INSTALL for load has 2 dialects (4-field vs 5-field) | Try both |
| 8 | BER-TLV length: 128-255 needs `81 xx`, 256+ needs `82 xx xx` | Use correct encoding |
| 9 | LOAD has 2 dialects (combined vs split blocks) | Try both |
| 10 | INSTALL for install has 2 dialects (SD vs instance AID) | Try both |
| 11 | PUT KEY: P2=0x81, no per-key ID bytes, keys encrypted with S-DEK | Follow exact encoding |
| 12 | ALG_AES_CMAC_128 (CMAC) is JC 3.0.5+; ALG_AES_MAC_128_NOPAD (CBC-MAC) is JC 2.2.2 - different constructions, NOT equivalent | Use matching SDK + host-side algorithm |
| 13 | EEPROM has finite write cycles | Don't loop install/delete unnecessarily |
| 14 | Cards wedge after unhappy sessions; reseat = power cycle | Always close sessions cleanly |
| 15 | GET STATUS P1 format varies (combined vs sequential) | Try P1=80/40/20 sequentially with P2=02 |
| 16 | Two LOAD dialects: combined (NXP) vs split (Mikron) | No universal format exists |
| 17 | Used dev cards arrive with unknown remaining write cycles (rated ~100K/cell, but history is invisible) | Treat used cards as consumables |

## Key discoveries

### The case-3 EXT AUTH bug

Every stock tool (GlobalPlatformPro, etc.) sends EXTERNAL AUTHENTICATE as case-4 (with a trailing Le byte). The firmware in this card batch rejects it with 6D00. Sending case-3 (without Le) is accepted. This is the single reason no standard tool can open these cards.

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

Neither card accepts the other's format. A hand-rolled installer must implement both.

## What worked and what didn't

| Card | LOAD | INSTALL | Notes |
|---|---|---|---|
| J3R150 #1 (used) | Combined format OK | 6985 locked | Code loaded, applet cannot be instantiated |
| J3R150 #2 (fresh) | Combined format OK | 6985 locked | Same lock on factory-fresh card |
| J3R150 #3 ("clean") | Combined format OK | 6985 locked | Entire batch is locked |
| Mikron (2019 dev card) | Split format OK (Windows/smacon) | OK (Windows/smacon) | Full cycle proven; card died during testing |

## Requirements

- macOS or Linux with PCSC (built into macOS)
- Python 3 with the `cryptography` package
- Any CCID smartcard reader
- Java Card SDK 3.0.5 or 2.2.2 (for building the CAP)

## Building the CAP

```bash
# Java Card 3.0.5
javac --release 7 -classpath sdk/jc305u2/lib/api.jar -d build applet/CollarMAC.java
java -Djc.home=sdk/jc305u2 -cp sdk/jc305u2/lib/converter.jar:... \
  com.sun.javacard.converter.Converter -config CollarMAC.opt

# Java Card 2.2.2 (for older cards)
javac --release 7 -classpath sdk/jc222/lib/api.jar -d build222 applet/CollarMAC222.java
# Then patch class major to 48 for the old converter
java -Djc.home=sdk/jc222 -cp sdk/jc222/lib/converter.jar:... \
  com.sun.javacard.converter.Converter -config CollarMAC222.opt
```

## License

MIT - same as the tutorial series. The applet code is yours to use, modify, and ship.

## Credit

The reverse-engineering path leaned on GlobalPlatformPro's open source (especially SCP02Wrapper.java and GPCrypto.java), the vendor's own Smacon tool logs from 2019, and a healthy disregard for the specification's claims of universality.

If your card accepts stock tools, use them. This kit exists for the cards that do not.
