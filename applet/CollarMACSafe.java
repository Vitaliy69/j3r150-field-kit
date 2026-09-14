package collarmac;

import javacard.framework.*;
import javacard.security.*;

public class CollarMACSafe extends Applet {
    private static final byte INS_MAC = 0x32;
    private static final byte INS_PERSO = 0x40;
    private static final byte INS_ALGO = 0x70;  // report which algorithm

    private AESKey aesKey;
    private DESKey desKey;
    private boolean personalized;
    private boolean useAES;
    private Signature mac;
    private byte[] scratch;

    public static void install(byte[] b, short o, byte l) {
        new CollarMACSafe().register();
    }

    private CollarMACSafe() {
        // try AES MAC first, catch and fall back to DES
        try {
            mac = Signature.getInstance(Signature.ALG_AES_MAC_128_NOPAD, false);
            aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            useAES = true;
        } catch (CryptoException e) {
            mac = Signature.getInstance(Signature.ALG_DES_MAC8_NOPAD, false);
            desKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);
            useAES = false;
        }
        scratch = JCSystem.makeTransientByteArray((short) 8, JCSystem.CLEAR_ON_RESET);
    }

    public void process(APDU apdu) {
        if (selectingApplet()) return;
        byte[] c = apdu.getBuffer();
        if (c[ISO7816.OFFSET_CLA] != (byte) 0x80)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        switch (c[ISO7816.OFFSET_INS]) {
            case INS_ALGO:  reportAlgo(apdu, c);  return;
            case INS_PERSO: personalize(apdu, c); return;
            case INS_MAC:   macCmd(apdu, c);      return;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void reportAlgo(APDU apdu, byte[] c) {
        c[0] = useAES ? (byte)1 : (byte)2;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    private void personalize(APDU apdu, byte[] c) {
        if (personalized) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        apdu.setIncomingAndReceive();
        try {
            if (useAES) {
                // data = 16-byte key (no wrap for simplicity — dev only)
                aesKey.setKey(c, ISO7816.OFFSET_CDATA);
                mac.init(aesKey, Signature.MODE_SIGN);
            } else {
                // data = 16-byte DES key
                desKey.setKey(c, ISO7816.OFFSET_CDATA);
                mac.init(desKey, Signature.MODE_SIGN);
            }
            personalized = true;
        } catch (CryptoException e) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
    }

    private void macCmd(APDU apdu, byte[] c) {
        if (!personalized) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        short lc = apdu.setIncomingAndReceive();
        try {
            short n = mac.sign(c, ISO7816.OFFSET_CDATA, lc, scratch, (short) 0);
            Util.arrayCopyNonAtomic(scratch, (short) 0, c, (short) 0, n);
            apdu.setOutgoingAndSend((short) 0, n);
        } catch (CryptoException e) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
    }
}
