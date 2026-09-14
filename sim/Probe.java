import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;
public class Probe extends Applet {
    public static void install(byte[] b, short o, byte l) {
        try {
            AESKey k = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            System.out.println("step1 buildKey OK: " + k);
            Signature s = Signature.getInstance(Signature.ALG_AES_CMAC_128, false);
            System.out.println("step2 getInstance OK: " + s);
            s.init(k, Signature.MODE_SIGN);
            System.out.println("step3 init OK");
            byte[] scr = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_RESET);
            System.out.println("step4 transient OK");
            byte[] in = new byte[]{0x51,0x42,0x43,0x44,0x45,0x46,0x47,0x48};
            short n = s.sign(in, (short)0, (short)8, scr, (short)0);
            StringBuilder sb = new StringBuilder("step5 sign OK: ");
            for (int i=0;i<n;i++) sb.append(String.format("%02X", scr[i]));
            System.out.println(sb);
            new Probe().register();
            System.out.println("step6 register OK");
        } catch (Throwable t) {
            System.out.println("PROBE FAIL: " + t.getClass().getName() + " / " + t.getMessage()
              + " / cause=" + (t.getCause()==null?"-":t.getCause().toString()));
            t.printStackTrace();
        }
    }
    public void process(APDU apdu) {}
}
