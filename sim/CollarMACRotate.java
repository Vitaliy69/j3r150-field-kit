package collarmac;

import javacard.framework.*;
import javacard.security.*;

public class CollarMACRotate extends Applet {
    private static final byte INS_MAC = 0x32;
    private static final byte INS_PERSO = 0x40;
    private static final byte INS_ROTATE = 0x42;
    // domain separation: every CMAC is computed over a one-byte context tag
    // prepended to the data, so a tag from one command can never be replayed
    // as authorization for another (the MAC command cannot produce a tag
    // that the ROTATE command would accept - and vice versa)
    private static final byte CTX_MAC = 0x01;
    private static final byte CTX_ROTATE = 0x02;
    private static final short MAX_MSG = 63;   // scratch holds ctx byte + message

    private static final byte[] FACTORY_TEST_KEY = {
        0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
        0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F };

    private AESKey transportKey;
    private AESKey deviceKey;
    private boolean personalized;
    private Signature mac;
    private byte[] msgBuf;   // ctx byte + message (transient)
    private byte[] tagBuf;   // tag output (transient)

    public static void install(byte[] b, short o, byte l) {
        new CollarMACRotate().register();
    }

    private CollarMACRotate() {
        transportKey = (AESKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        transportKey.setKey(FACTORY_TEST_KEY, (short) 0);
        deviceKey = (AESKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        // deliberately no mac.init() here: initializing a MAC engine over a
        // key that has no value yet throws a CryptoException on a real card.
        // An emulator taught us that before the hardware could.
        mac = Signature.getInstance(Signature.ALG_AES_CMAC_128, false);
        msgBuf = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_RESET);
        tagBuf = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_RESET);
    }

    public void process(APDU apdu) {
        if (selectingApplet()) return;
        byte[] c = apdu.getBuffer();
        if (c[ISO7816.OFFSET_CLA] != (byte) 0x80)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if (c[ISO7816.OFFSET_P1] != 0 || c[ISO7816.OFFSET_P2] != 0)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        switch (c[ISO7816.OFFSET_INS]) {
            case INS_PERSO: personalize(apdu, c); return;
            case INS_ROTATE: rotate(apdu, c); return;
            case INS_MAC:   macCommand(apdu, c);  return;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    // read the full incoming data field, rejecting partial claims:
    // setIncomingAndReceive may deliver only the first chunk on transports
    // that split the data, so receiveBytes() finishes the job and a mismatch
    // with the announced Lc is a hard error (tutorial strictness)
    // strict input: first chunk arrives, THEN the announced length is
    // validated against the command's bounds (before any further receiveBytes
    // could overflow the buffer), then the rest of the field is read.
    // (getIncomingLength() is not reliable before the first receive on all
    // runtimes - a simulator taught us that one.)
    private short receiveAll(APDU apdu, byte[] c, short min, short max) {
        short total = apdu.setIncomingAndReceive();
        short expected = apdu.getIncomingLength();
        if (expected < min || expected > max)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        while (total < expected) {
            short n = apdu.receiveBytes((short) (ISO7816.OFFSET_CDATA + total));
            if (n <= 0) break;
            total += n;
        }
        if (total != expected)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        return total;
    }

    private void personalize(APDU apdu, byte[] c) {
        if (personalized) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        short total = receiveAll(apdu, c, (short) 32, (short) 32);
        // expects: 16-byte key || its full 16-byte CMAC under the transport key
        mac.init(transportKey, Signature.MODE_VERIFY);
        if (!mac.verify(c, ISO7816.OFFSET_CDATA, (short) 16,
                        c, (short) (ISO7816.OFFSET_CDATA + 16), (short) 16))
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        deviceKey.setKey(c, ISO7816.OFFSET_CDATA);
        mac.init(deviceKey, Signature.MODE_SIGN);
        personalized = true;
    }

    private void macCommand(APDU apdu, byte[] c) {
        if (!personalized) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        short total = receiveAll(apdu, c, (short) 1, MAX_MSG);
        // re-init on every call: a failed ROTATE leaves the engine in
        // MODE_VERIFY, and signing with a verify-mode engine throws
        msgBuf[0] = CTX_MAC;
        Util.arrayCopyNonAtomic(c, ISO7816.OFFSET_CDATA, msgBuf, (short) 1, total);
        mac.init(deviceKey, Signature.MODE_SIGN);
        short n = mac.sign(msgBuf, (short) 0, (short) (total + 1), tagBuf, (short) 0);
        Util.arrayCopyNonAtomic(tagBuf, (short) 0, c, (short) 0, n);
        apdu.setOutgoingAndSend((short) 0, n);
    }

    private void rotate(APDU apdu, byte[] c) {
        if (!personalized) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        short total = receiveAll(apdu, c, (short) 32, (short) 32);
        // expects: 16-byte new key || CMAC(current device key, CTX_ROTATE || new key)
        msgBuf[0] = CTX_ROTATE;
        Util.arrayCopyNonAtomic(c, ISO7816.OFFSET_CDATA, msgBuf, (short) 1, (short) 16);
        mac.init(deviceKey, Signature.MODE_VERIFY);
        if (!mac.verify(msgBuf, (short) 0, (short) 17,
                        c, (short) (ISO7816.OFFSET_CDATA + 16), (short) 16)) {
            // restore the sign mode before refusing: the caller's next
            // ordinary MAC must not pay for our failed verification
            mac.init(deviceKey, Signature.MODE_SIGN);
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        deviceKey.setKey(c, ISO7816.OFFSET_CDATA);
        mac.init(deviceKey, Signature.MODE_SIGN);
    }
}
