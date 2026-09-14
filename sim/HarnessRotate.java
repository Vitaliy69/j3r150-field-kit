import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class HarnessRotate {
    static String h(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02X", x));
        return s.toString();
    }
    static byte[] hx(String s) {
        byte[] b = new byte[s.length()/2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(s.substring(2*i, 2*i+2), 16);
        return b;
    }
    static final String PERSO = "000102030405060708090A0B0C0D0E0FF3F8F9FF1F19657B18DC28FC42FBAAAD";
    static final String ROT_GOOD = "101112131415161718191A1B1C1D1E1F5328320C5D7BF725945A958F63AAF082";
    static final String ROT_BAD  = "101112131415161718191A1B1C1D1E1F00000000000000000000000000000000";
    static final String MAC_K1 = "7E52D227E20BA4C3EA70A8E5DF2BDA32";
    static final String MAC_K2 = "571998BB31E0889E94AB13AF3206D33E";
    static final byte[] CH = {0x51,0x42,0x43,0x44,0x45,0x46,0x47,0x48};

    public static void main(String[] a) throws Exception {
        CardSimulator sim = new CardSimulator();
        byte[] aidB = {(byte)0xF0,0,0,0,1,(byte)0xDE,(byte)0xAD,0x01};
        AID aid = AIDUtil.create(aidB);
        sim.installApplet(aid, collarmac.CollarMACRotate.class);
        sim.selectApplet(aid);

        ResponseAPDU r = sim.transmitCommand(new CommandAPDU((byte)0x80,0x32,0,0,CH));
        System.out.println("1) MAC before perso      : SW=" + String.format("%04X", r.getSW()) + "  (expect 6985)");

        r = sim.transmitCommand(new CommandAPDU((byte)0x80,0x40,0,0,hx(PERSO)));
        System.out.println("2) personalize (K1)      : SW=" + String.format("%04X", r.getSW()) + "  (expect 9000)");

        r = sim.transmitCommand(new CommandAPDU((byte)0x80,0x32,0,0,CH));
        System.out.println("3) MAC under K1          : SW=" + String.format("%04X", r.getSW())
            + "  tag=" + h(r.getData()) + "  " + (MAC_K1.equals(h(r.getData())) ? "MATCH K1" : "MISMATCH"));

        r = sim.transmitCommand(new CommandAPDU((byte)0x80,0x42,0,0,hx(ROT_BAD)));
        System.out.println("4) rotate BAD wrap       : SW=" + String.format("%04X", r.getSW()) + "  (expect 6982)");

        r = sim.transmitCommand(new CommandAPDU((byte)0x80,0x42,0,0,hx(ROT_GOOD)));
        System.out.println("5) rotate good (K1->K2)  : SW=" + String.format("%04X", r.getSW()) + "  (expect 9000)");

        r = sim.transmitCommand(new CommandAPDU((byte)0x80,0x32,0,0,CH));
        System.out.println("6) MAC under K2          : SW=" + String.format("%04X", r.getSW())
            + "  tag=" + h(r.getData()) + "  " + (MAC_K2.equals(h(r.getData())) ? "MATCH K2 - KEY ROTATED" : "MISMATCH"));
    }
}
