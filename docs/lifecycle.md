# One device key's life

Run `python3 examples/collar_lifecycle.py` with `cryptography` installed.
The article embeds this same source.

| Stage | Device-key operation | Evidence |
|---|---|---|
| Generate | Host generates 16 random bytes | Python example |
| Personalize | INS 40: key + CMAC under the applet transport key; one-shot | Transcripts 39/41 |
| Authenticate | INS 32: CMAC(deviceKey, 01 || challenge) | Transcript 41 |
| Rotate | INS 42: newKey + CMAC(oldKey, 02 || newKey) | Transcript 41 |
| Revoke | Backend rejects the device; the card can still compute tags | Python example |

ISD management keys are separate. SCP02 derives session keys from them;
EXT AUTH authenticates a management session, PUT KEY changes the management
keyset, and DELETE removes installed content. DELETE is not backend revocation.

## What the example checks

- Personalization is one-shot and validates the packet length and CMAC.
- Ordinary MAC tags cannot authorize ROTATE, including under `python3 -O`.
  Security checks use exceptions rather than assertions.
- The backend accepts only its outstanding challenge and consumes it on success.
  Issuing another challenge invalidates the previous one.
- Rotation leaves the old backend key active until the card returns a valid
  MAC under the proposed new key.
- Revocation rejects even a valid response to an earlier challenge.

Expected output:

```text
1) personalized at production, enrolled on backend
2) auth: accepted (round 1)
2) auth: accepted (round 2)
3) forgery via plain MAC rejected (domain separation holds)
   rotated: card and backend both hold fresh keys
4) auth with fresh key: accepted
5) after revocation: REJECTED: unknown or revoked device
   the card itself still MACs fine - it is healthy, just orphaned
```

## Scope

CardStub models command behavior, not secret isolation: Python attributes are
readable. The key-plus-MAC packets are plaintext with integrity, not encrypted
wrapping. Both card and verifier hold the shared device key.

The backend is in memory, with one outstanding challenge and one pending
rotation per device. Durable storage, crash recovery, rotation retry after a
lost response, concurrency, and challenge expiry need an explicit production
design. These are not claimed as hardware tests.

The canonical applet is `sim/CollarMACRotate.java`; the earlier
`applet/CollarMAC.java` has a different, unprefixed MAC protocol.
Transcript 39 predates domain separation; transcript 41 covers the current
domains and rotation. Use a matching host calculation and CAP.

A holder of a compromised current device key can authorize rotation too.
Recovering ownership then requires a separate trusted provisioning procedure.
Public factory test keys are for the bench only.
