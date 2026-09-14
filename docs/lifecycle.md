# One key's whole life

The tutorial series describes the device-key lifecycle as the actual product:
a key is generated, provisioned, operated, rotated, and revoked. This document
maps every stage onto two things you can run directly:

1. `examples/collar_lifecycle.py` - the whole lifecycle as one script, no card
   required. The card side is a stub that computes byte-for-byte what the
   applet computes (AES-CMAC over the same bytes).
2. The real transcripts in `transcripts/` - the same ceremony on hardware.

## The map

| Stage | Concrete operation | Where in this repo |
|---|---|---|
| Generate | Session keys derived per-session from the master keyset and the card's challenge | `transcripts/03_j3r150_manual_scp02_success.txt` |
| Provision (card keys) | PUT KEY: replace the ISD keyset (batch keys to factory keys, version FF to 01, three KCV confirmations) | `transcripts/04_j3r150_putkey_batch_to_factory.txt` |
| Provision (applet keys) | PERSONALIZE (INS 0x40): device key injected under the transport key, CMAC-verified, stored in EEPROM. One-shot by design | `transcripts/11_j3r150_cmac_verify_session.txt` |
| Operate | EXT AUTH every session: the card verifies a cryptogram over both challenges | `transcripts/03_j3r150_manual_scp02_success.txt` |
| Rotate | PUT KEY under a new version number; the old keyset stays valid until the card switches. Applet-level: INS_ROTATE below | `transcripts/04_j3r150_putkey_batch_to_factory.txt` |
| Revoke | DELETE removes the applet and its persistent state - keys, counters, flags | `transcripts/08_j3r150_load_success_install_locked.txt` |

## The script

    /usr/bin/python3 examples/collar_lifecycle.py

Expected output - the biography of one key:

    1) personalized at production, enrolled on backend
    2) auth: accepted
    2) auth: accepted
    3) rotated: card and backend both hold fresh keys
    4) auth with fresh key: accepted
    5) after revocation: REJECTED: unknown or revoked device
       the card itself still MACs fine - it is healthy, just orphaned

Read the last two lines twice. Revocation is not an instruction you send to a
stolen card - a stolen card would ignore it anyway. Revocation is a fact the
backend knows and the card never learns. The chip keeps computing perfect MACs
with a perfectly good key; the server simply stops caring.

## The applet-side rotation (INS 0x42)

The listing in `applet/` enrolls the key via INS_PERSO (0x40). Rotation is one
more instruction that refuses to do anything useful without proof of the
current key. Append to the applet:

```java
private static final byte INS_ROTATE = 0x42;

// in process(), one more case:
case INS_ROTATE: {
    if (!personalized) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    apdu.setIncomingAndReceive();
    // expects: 16-byte new key || its full 16-byte CMAC under the *current* device key
    mac.init(deviceKey, Signature.MODE_VERIFY);
    if (!mac.verify(c, ISO7816.OFFSET_CDATA, (short) 16,
                    c, (short) (ISO7816.OFFSET_CDATA + 16), (short) 16))
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    deviceKey.setKey(c, ISO7816.OFFSET_CDATA);
    mac.init(deviceKey, Signature.MODE_SIGN);   // re-bind the engine to the new value
    return;
}
```

Notice what it does not contain: any way to read the old key out, and any way
to install a new one without proving knowledge of the current one.

## Production note

The bench scripts use the factory transport key from the documentation - fine
for a tutorial, fatal in a product. A production line derives a per-device
transport key on a hardware security module, injects it during applet
installation, and the personalization station knows exactly one device's
secret at exactly one moment, under split-knowledge controls: no single
person, and no single machine, ever holds enough to clone a device.

The series this kit accompanies starts with
[Securing a Smart Dog Collar (HackerNoon)](https://hackernoon.com/securing-a-smart-dog-collar-secure-elements-key-lifecycles-and-why-tls-isnt-enough-on-5-microamp).
