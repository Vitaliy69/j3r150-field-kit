import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class CollarMAC_SIM2 extends Applet {
    private static final byte INS_MAC = 0x32;
    private Signature mac;
    private byte[] scratch;

    public static void install(byte[] b, short o, byte l) {
        new CollarMAC_SIM2().register();
    }

    private CollarMAC_SIM2() {
        AESKey k = (AESKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        // the key value arrives at personalization, not at compile time;
        // there is deliberately no setKey() call with a constant anywhere
        mac = Signature.getInstance(Signature.ALG_AES_CMAC_128, false);
        k.setKey(new byte[]{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, (short)0); mac.init(k, Signature.MODE_SIGN); // sim stand-in for personalization
        scratch = JCSystem.makeTransientByteArray(
                (short) 16, JCSystem.CLEAR_ON_RESET);
    }

    public void process(APDU apdu) {
        if (selectingApplet()) return;
        byte[] c = apdu.getBuffer();
        if (c[ISO7816.OFFSET_CLA] != (byte) 0x80)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if (c[ISO7816.OFFSET_INS] != INS_MAC)
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        if (c[ISO7816.OFFSET_P1] != 0 || c[ISO7816.OFFSET_P2] != 0)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        short lc = apdu.setIncomingAndReceive();
        short n = mac.sign(c, ISO7816.OFFSET_CDATA, lc, scratch, (short) 0);
        Util.arrayCopyNonAtomic(scratch, (short) 0, c, (short) 0, n);
        apdu.setOutgoingAndSend((short) 0, n);
    }
}
