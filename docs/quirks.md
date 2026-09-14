# Firmware misbehavior catalog

Observed on both cards of batch PI260905-2133 (ISD reports SCP02, key version 0xFF). All items reproduced multiple times.

## 1. EXTERNAL AUTHENTICATE rejects the trailing Le byte

The same command, two formats:

- `84 82 01 00 10 <16 bytes> 00` (case-4, Le present) -> 6D00, "Invalid INStruction"
- `84 82 01 00 10 <16 bytes>` (case-3, no Le) -> processed, reaches the cryptographic check

Every release of GlobalPlatformPro tested (v25.10.20, v26.06.04, v20.08.12) sends case-4. Therefore no stock tool can open this card, with any keys.

## 2. Status words lie about available length

INITIALIZE UPDATE answers `61 12` (18 bytes promised) or `61 1C` (28 promised) nondeterministically for the same command. GET RESPONSE delivers whatever it likes: sometimes the full 28 bytes, sometimes 26 of them (the card cryptogram arrives truncated by two bytes). Treat SW2 as a hint, not a contract; retry INIT UPDATE with a fresh host challenge until a full-length answer arrives.

## 3. Greedy GET RESPONSE is punished

Requesting more than SW2 promised (for example Le=0xE0) returns 6985, "conditions of use not satisfied". Ask for exactly SW2.

## 4. Wedges after unhappy sessions

After a failed or half-finished secure-channel sequence the card stops answering until physically reseated. A reseat is a power cycle; no PCSC-level reset recovered it in our tests.

## 5. The card challenge is not random

Across five sessions with five different host challenges, the card produced three distinct "random" challenges, two of them twice each. Observed values: 0008E0E074A4BCAC, 00055AB524F51185, 00046A7DAECDC988. The GP specification requires an unpredictable challenge; a repeating one undermines the replay protection the handshake exists to provide.

## 6. SELECT moods

Immediately after a cold start the ISD SELECT sometimes answers 6985 or 6C 12 (with a Le hint) instead of the expected 9000 or 61xx. A retry or a reseat settles it. We found no pattern; we found patience works.

## GET STATUS 6310 desyncs a naive C-MAC chain (observed Sep 17)

A sequential registry read (P1 80/40/20, P2=0x02) answered `6310` (more data)
on the load-files section. The card had executed the command and advanced its
C-MAC chain, but a client that only advances its ICV on `9000` sends the next
command with a stale MAC - which surfaces as `6982` on that command. If you
need the registry mid-session, either implement the `6310` continuation and
ICV handling properly, or read the registry in a session of its own. In this
kit the load stage therefore runs the proven DELETE -> INSTALL -> LOAD ->
INSTALL sequence by default; pass `--registry` to opt into the registry read.
