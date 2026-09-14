package collarmac;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class CollarMAC extends Applet {
    private static final byte INS_MAC = 0x32;
    private static final byte INS_PERSO = 0x40;
    private static final byte[] FACTORY_TEST_KEY = {
        0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
        0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F };

    private AESKey transportKey;   // held as a field, not a local - it persists
    private AESKey deviceKey;      // same: fields persist in EEPROM
    private boolean personalized;  // a boolean field persists in EEPROM
    private Signature mac;
    private byte[] scratch;

    public static void install(byte[] b, short o, byte l) {
        new CollarMAC().register();
    }

    private CollarMAC() {
        transportKey = (AESKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        transportKey.setKey(FACTORY_TEST_KEY, (short) 0);   // bench only: the dev
        // card's public factory test key; a product derives per-device keys on an HSM
        deviceKey = (AESKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        // deliberately no setKey() with a constant for the device key, and
        // deliberately no mac.init() here: initializing a MAC engine over a
        // key that has no value yet throws a CryptoException on a real card.
        // An emulator taught us that before the hardware could.
        mac = Signature.getInstance(Signature.ALG_AES_CMAC_128, false);
        scratch = JCSystem.makeTransientByteArray(
                (short) 16, JCSystem.CLEAR_ON_RESET);
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
            case INS_MAC:   macCommand(apdu, c);  return;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void personalize(APDU apdu, byte[] c) {
        if (personalized) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        apdu.setIncomingAndReceive();
        // expects: 16-byte key || its full 16-byte CMAC, under the transport key
        mac.init(transportKey, Signature.MODE_VERIFY);
        if (!mac.verify(c, ISO7816.OFFSET_CDATA, (short) 16,
                        c, (short) (ISO7816.OFFSET_CDATA + 16), (short) 16))
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        deviceKey.setKey(c, ISO7816.OFFSET_CDATA);
        mac.init(deviceKey, Signature.MODE_SIGN);   // now, and only now, signing works
        personalized = true;   // one shot - this instruction never works again
    }

    private void macCommand(APDU apdu, byte[] c) {
        if (!personalized) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        short lc = apdu.setIncomingAndReceive();
        short n = mac.sign(c, ISO7816.OFFSET_CDATA, lc, scratch, (short) 0);
        Util.arrayCopyNonAtomic(scratch, (short) 0, c, (short) 0, n);
        apdu.setOutgoingAndSend((short) 0, n);
    }
}
