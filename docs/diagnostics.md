# Diagnostics: separate the client, reader, and card

The malformed INSTALL and broken Python PC/SC binding were client bugs.
The later reconnect failure is a separate, reproducible observation. It
does not prove that the card or seller is at fault.

## Independent checks on 2026-09-18

Setup: macOS 26.7, Generic EMV Smartcard Reader (USB 058F:9540), T=0.
The reader was connected through an Apple USB hub.

- GPPro v25.10.20 with Homebrew Java 21.0.12 returned `6D00` for case-4
  EXTERNAL AUTHENTICATE through javax.smartcardio. This reproduced the failure
  without the Python transport. It does not identify the rejecting layer or
  establish failure for every GPPro release.
- Native C programs compiled against Apple's PC/SC headers reproduced a
  failed reconnect using only SELECT ISD and GET RESPONSE. No authentication,
  key changes, applet installation, or rotation was needed.
- After disconnect with LEAVE_CARD, reconnect failed with `0x80100066`.
- Holding the same handle open for 120 seconds without APDUs allowed another
  successful SELECT. After closing it, an independent connect failed 14 seconds later.
- Disconnect with UNPOWER_CARD did not help: reconnect failed after 10.8 seconds.
- The USB reader kept the same IORegistry identity. PC/SC still reported PRESENT
  and a cached ATR; neither proves that a new connection will work.

Exact APDUs and observation times: [transcript 42](../transcripts/42_reviewer_gppro_and_reconnect.txt).

## Practical workaround and limits

Reseat the card before a new CLI session on a setup that exhibits this failure.
For a multi-operation diagnostic, retain one connection until the sequence ends.
The two-minute HOLD result supports that workaround for the tested interval;
it is not a permanent fix. Periodic keepalive APDUs were not needed in that test.

The kit's four quick-start commands are separate processes. They do not share
a handle. Closing resources correctly does not, by itself, cure this reconnect
failure. After a PC/SC error, stop; do not continue an old secure-channel MAC chain.

A second reader, another OS, or a controlled protocol comparison is needed to
separate card activation, reader firmware, and the macOS driver. We do not have
that comparison. The measured times are probe times, not a discovered idle timer.

## Other limits

- Registry contents do not establish fuse state or payment personalization.
- Loading a CAP built against an SDK establishes compatibility with the APIs
  exercised by that applet, not the full OS version.
- Historical repeated card challenges need a clean re-test with sequence
  counters and successful session boundaries recorded. SCP02 permits a
  pseudorandom challenge; repetitions during failed handshakes alone do not
  prove a broken random generator.
