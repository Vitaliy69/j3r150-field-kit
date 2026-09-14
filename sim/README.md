# jCardSim test bench

Emulator-based dry-run of the CollarMAC applet, verified before touching
real hardware. The simulator caught a real bug: initializing a MAC engine
over an uninitialized key throws CryptoException on a real card.

## Files

- `jcardsim-3.0.6.0.jar` - self-contained (Java Card API + BouncyCastle bundled).
  Tested on JDK 21 (Homebrew, macOS).
- `CollarMAC_SIM2.java` - working variant: `ALG_AES_CMAC_128` + `setKey(zeros)`
  in the constructor as a personalization stub.
- `Harness2.java` - full transcript: select before install, install+select,
  wrong INS (6D00), wrong CLA (6E00), MAC (16 bytes + 9000).
- `Probe.java` - step-by-step constructor crash isolation (this is how the
  CryptoException in `SymmetricSignatureImpl.init` with an unset key was found).

## Run

```bash
javac -classpath jcardsim-3.0.6.0.jar CollarMAC_SIM2.java Harness2.java
java  -classpath .:jcardsim-3.0.6.0.jar Harness2
```

## Expected output

```
1) SELECT before install : SW=6999
2) install+select          : true
3) INS 0x99              : SW=6D00
4) CLA 0x00              : SW=6E00
5) MAC (key = zeros)     : SW=9000  CMAC=F6EA26D7163296A57F836B831FD6B1EE  len=16
```

## Host-side verification (Python)

```bash
python3 -c "
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms
c = cmac.CMAC(algorithms.AES(bytes(16)))
c.update(bytes.fromhex('5142434445464748'))
print(c.finalize().hex().upper())"
```

Expected CMAC (key = 16 zero bytes, challenge = 5142434445464748):
`F6EA26D7163296A57F836B831FD6B1EE` - simulator and Python match byte-for-byte.

## Known differences from a real card

- SELECT of an unknown AID before install: simulator answers 6999, a real
  card answers 6A82.
- An install crash surfaces as a bare `SystemException: null` (the real
  cause is only visible from inside `install()`).

## HarnessRotate - the INS_ROTATE (0x42) proof

`CollarMACRotate.java` is the article's applet listing plus the rotation delta from
`docs/lifecycle.md`. `HarnessRotate.java` runs the full ceremony on the simulator:

```
1) MAC before perso      : SW=6985  (one-shot rule: no key, no MAC)
2) personalize (K1)      : SW=9000
3) MAC under K1          : tag = 7E52D227...  MATCH (python-computed vector)
4) rotate BAD wrap       : SW=6982  (refuses without proof of the current key)
5) rotate good (K1->K2)  : SW=9000
6) MAC under K2          : tag = 571998BB...  MATCH K2 - KEY ROTATED
```

All tags are byte-exact against independently computed CMAC vectors; the same
test vectors drive `examples/collar_lifecycle.py`. Build and run exactly like
the other harnesses (`sdk/jc305u2` + `jcardsim-3.0.6.0.jar` on the classpath).
