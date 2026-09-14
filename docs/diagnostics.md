# Diagnostics: card vs reader vs driver

Question: which layer of "hostility" is the card's firmware, and which is the
reader (Generic EMV Smartcard Reader) or the macOS PCSC driver?

## Solidly attributed to the card

- **The static card challenge.** Across five sessions with five different host
  challenges the card produced three distinct "random" challenges, two of them
  twice. The challenge is generated on-card; the reader only carries bytes.
  A repeating challenge is a firmware/spec violation.
- **6985 for oversized GET RESPONSE** and **6112/611C for promised lengths** -
  on-card state machine semantics, consistent across our tooling.
- **The case-3/case-4 split reached the card.** Through the same reader and the
  same pipe: `84 82 01 00 10 <16>` answered 6982 (live crypto check), while the
  same command plus a trailing `00` answered 6D00. The reader passed both
  formats; the card distinguished them. The Le-sensitivity is the card's.

## Could still be reader/driver

- **Response truncation** (26 of 28 bytes of INIT UPDATE): could be the CCID
  reader buffer, the driver, or the card. Discriminator: same card in a second
  reader (or NFC contactless from a phone - the J3R150 is dual-interface).
- **Post-session wedges**: could be the reader keeping the card powered in a
  stuck protocol state rather than the card itself.

## Probes to run (one reseat per probe, SELECT-only ones are always safe)

1. **JCOP fusion state** (answers the "unfused?" question directly):

       00 A4 04 00 08 A0 00 00 01 67 41 30 00 FF

   IDENTIFY applet. SW 9000: byte at offset 14 of the data - 00h = unfused,
   01h = fused/configured. SW 6A82: no IDENTIFY applet (expected on JCOP4 -
   the mechanism is documented for JCOP21-era chips; on JCOP4 its absence is
   uninformative).

2. **Transport key as AID** (legacy init path, JCOP21-era):

       00 A4 04 00 10 C2 38 E4 49 F7 25 B1 51 0E AA 69 95 50 CA BA 16

   9000 = the legacy init path exists (do NOT run the key-write/fuse commands
   without a plan). 6A82 = path absent.

3. **Force T=1**: connect with protocol mask 0x02 only. If the card supports
   T=1, the case-4 EXT AUTH may pass naturally (T=1 carries Le in-band) - this
   discriminates "card rejects Le" from "T=0 framing quirk".

4. **Cross-reader**: same card in a second reader model (or via NFC from an
   Android phone with a GP-capable app). If the 6D00-on-Le follows the card to
   another reader, it is the card. If it disappears, it was the pipe.

5. **CPLC cross-check**: run the CPLC read on BOTH cards of the batch and
   compare ICFabricator/ICType/serials. Ours: ICFabricator 0x4790, ICType D321.
   If the two cards differ in CPLC, the "batch" assumption is wrong too.

## What we still do not know

- The real Java Card OS version: 2.2.2, 3.0.4 or 3.0.5 (ATR is spoofable;
  CPLC does not carry it; only building and installing an applet answers this (the converter version tells you the API level the card accepts)).
- The fusion state (probe: JCOP IDENTIFY).
- The attribution of the 6D00-on-Le (card vs reader/driver: the T=1 and cross-reader probes).
- The source of response truncation (probe with second reader).
