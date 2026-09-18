# Observations and corrections

Keep client failures separate from card behavior. Historical transcripts retain
their original hypotheses; this file records the current interpretation.

## Confirmed client bugs, corrected

- A GET RESPONSE assembler stripped SW twice, turning a 28-byte INIT UPDATE
  payload into 26 bytes. This was not firmware truncation.
- An incorrect Apple PC/SC binding used the wrong structure size, passed an
  extra argument, and ignored return codes. A zero-filled receive buffer was
  mistaken for a SELECT hang.
- INSTALL used the ISD AID in the instance slot and omitted the token length.
  The standard encoding succeeded.
- INSTALL for load also has five standard fields: load-file AID, SD AID,
  hash, load parameters, Load Token. An empty value still has a length field.
  There is no extra signature slot between hash and parameters.

The three Python clients now share `scripts/pcsc_mac.py`: Apple ABI types,
return-code checks, cleanup, and one continuation loop for `61xx`/`6Cxx`.
Transport errors are reported separately from APDU status words.

The historical `probe_extauth.py` also retained the defective binding and
reused a failed session for dummy-cryptogram variants. It is now an archive
notice that sends no APDUs. The invalid `install03` wrapping experiment is
archived as well; neither stage is a working installation recipe.

## Case-3 and case-4 EXT AUTH

Case-3 succeeded in the working sessions. Independent GPPro v25.10.20,
javax.smartcardio, macOS 26.7, Generic EMV reader, T=0: case-4 returned `6D00`
(transcript 42). This is no longer dependent on the old Python binding.
The cause within the card/reader/driver path is not isolated. Older runs with
other tool versions are historical observations, not a universal tool verdict.

## Reconnect after a successful session

A SELECT-only native PC/SC experiment reproduced `0x80100066` after disconnect.
An open handle survived 120 seconds without APDUs. UNPOWER at disconnect did
not repair reconnect. See [diagnostics](diagnostics.md) and transcript 42.

## SCP02 details

The working client uses encrypted ICV chaining after EXT AUTH. The previous
claim that `i=02` mandated encryption was wrong: the ICV-encryption option is
bit `0x10` in GP 2.2.1 Appendix E.1.1. Do not infer the option from the SCP
identifier byte in INITIALIZE UPDATE.

The repeated challenge values in early traces remain observations to re-test
with the corrected transport. They do not establish a defective random generator.

## Historical GET RESPONSE and SELECT variations

Oversized GET RESPONSE requests and cold-start SELECT variations were logged
with the old transport. Ask for the announced length and follow `6Cxx`
corrections; do not attribute those historical errors to firmware without a
controlled independent reproduction.

## Registry continuation

GET STATUS can answer `6310`: the command was processed, with more registry
entries available. Continue with the same P1 and P2=`03`, advancing the C-MAC
chain. The client now collects these pages and stops on an unexpected status.
