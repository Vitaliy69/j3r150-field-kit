import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

// Test protocol (per independent review): happy path, the cross-domain
// forgery that the old build allowed, stale-engine recovery after a failed
// ROTATE, and CMAC boundary lengths 1/15/16/17/31/32 against host-computed
// tags. All expected tags computed independently (python cryptography).
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
    static int pass = 0, fail = 0;
    static void check(String name, boolean ok, String extra) {
        if (ok) { pass++; System.out.println("PASS  " + name + "  " + extra); }
        else    { fail++; System.out.println("FAIL  " + name + "  " + extra); }
    }
    static String sw(ResponseAPDU r) { return String.format("%04X", r.getSW()); }

    static final String PERSO     = "000102030405060708090A0B0C0D0E0FF3F8F9FF1F19657B18DC28FC42FBAAAD";
    static final String ROT_GOOD  = "101112131415161718191A1B1C1D1E1FC1E4743E78478C56DBB7CCC0D82688BA";
    static final String ROT_FORGE = "101112131415161718191A1B1C1D1E1F9DF5162AD5209FDA1EE12097E6CE1EE0";
    static final String ROT_BAD   = "101112131415161718191A1B1C1D1E1F00000000000000000000000000000000";
    static final String MAC_K1_CH = "B547D898956AF64ED4DCEA32987426C1";
    static final String MAC_K2_CH = "D2011C73250BF215D3F5F0EB005C38A1";
    static final byte[] CH = {0x51,0x42,0x43,0x44,0x45,0x46,0x47,0x48};
    static final byte[] M  = new byte[32];   // 010203..20
    static { for (int i = 0; i < 32; i++) M[i] = (byte)(i + 1); }
    static final String[] B_TAGS = {
        // n=1, 15, 16, 17, 31, 32 (host-computed CMAC(K1, 0x01 || msg))
        "18A93141F1F4DE4F8B59A89210ECF6EE",
        "C3AA54177E2838490CBA45EBA390E38B",
        "20F1119DBF785E20AE1E8235AC34FEAC",
        "B73E7FDD4C6216963AA30BFBB48BC149",
        "6E4D6D7D5AADBED9994CFB804A9A872F",
        "75DED55237B1EFE41DE9C80E98C7ABCF",
    };
    static final int[] B_LENS = {1, 15, 16, 17, 31, 32};

    public static void main(String[] a) throws Exception {
        CardSimulator sim = new CardSimulator();
        byte[] aidB = {(byte)0xF0,0,0,0,1,(byte)0xDE,(byte)0xAD,0x01};
        AID aid = AIDUtil.create(aidB);
        sim.installApplet(aid, collarmac.CollarMACRotate.class);
        sim.selectApplet(aid);

        ResponseAPDU r = sim.transmitCommand(new CommandAPDU((byte)0x80,0x32,0,0,CH));
        check("1  MAC before perso     ", r.getSW() == 0x6985, "SW=" + sw(r));

        r = sim.transmitCommand(new CommandAPDU((byte)0x80,0x40,0,0,hx(PERSO.substring(0,62))));
        check("2  perso 31B rejected   ", r.getSW() == 0x6700, "SW=" + sw(r));

        byte[] p33 = new byte[33]; System.arraycopy(hx(PERSO), 0, p33, 0, 32); p33[32] = 0;
        r = sim.transmitCommand(new CommandAPDU((byte)0x80,0x40,0,0,p33));
        check("3  perso 33B rejected   ", r.getSW() == 0x6700, "SW=" + sw(r));

        r = sim.transmitCommand(new CommandAPDU((byte)0x80,0x40,0,0,hx(PERSO)));
        check("4  personalize (K1)     ", r.getSW() == 0x9000, "SW=" + sw(r));

        r = sim.transmitCommand(new CommandAPDU((byte)0x80,0x32,0,0,CH));
        check("5  MAC under K1         ", r.getSW() == 0x9000 && MAC_K1_CH.equals(h(r.getData())),
              "SW=" + sw(r) + " tag=" + h(r.getData()));

        for (int i = 0; i < B_LENS.length; i++) {
            byte[] m = new byte[B_LENS[i]];
            System.arraycopy(M, 0, m, 0, B_LENS[i]);
            r = sim.transmitCommand(new CommandAPDU((byte)0x80,0x32,0,0,m));
            check("6" + (i+1) + " MAC len " + String.format("%02d", B_LENS[i]) + "        ",
                  r.getSW() == 0x9000 && B_TAGS[i].equals(h(r.getData())),
                  "SW=" + sw(r) + " tag=" + h(r.getData()));
        }

        r = sim.transmitCommand(new CommandAPDU((byte)0x80,0x42,0,0,hx(ROT_FORGE)));
        check("7  FORGE cross-domain   ", r.getSW() == 0x6982,
              "SW=" + sw(r) + "  (old build accepted this!)");

        r = sim.transmitCommand(new CommandAPDU((byte)0x80,0x32,0,0,CH));
        check("8  MAC after failed rot ", r.getSW() == 0x9000 && MAC_K1_CH.equals(h(r.getData())),
              "SW=" + sw(r) + "  (stale-engine fix)");

        r = sim.transmitCommand(new CommandAPDU((byte)0x80,0x42,0,0,hx(ROT_BAD)));
        check("9  rotate BAD wrap      ", r.getSW() == 0x6982, "SW=" + sw(r));

        r = sim.transmitCommand(new CommandAPDU((byte)0x80,0x42,0,0,hx(ROT_GOOD.substring(0,62))));
        check("10 rotate 31B rejected  ", r.getSW() == 0x6700, "SW=" + sw(r));

        byte[] r33 = new byte[33]; System.arraycopy(hx(ROT_GOOD), 0, r33, 0, 32); r33[32] = 0;
        r = sim.transmitCommand(new CommandAPDU((byte)0x80,0x42,0,0,r33));
        check("11 rotate 33B rejected  ", r.getSW() == 0x6700, "SW=" + sw(r));

        r = sim.transmitCommand(new CommandAPDU((byte)0x80,0x42,0,0,hx(ROT_GOOD)));
        check("12 rotate good (K1->K2) ", r.getSW() == 0x9000, "SW=" + sw(r));

        r = sim.transmitCommand(new CommandAPDU((byte)0x80,0x32,0,0,CH));
        check("13 MAC under K2         ", r.getSW() == 0x9000 && MAC_K2_CH.equals(h(r.getData())),
              "SW=" + sw(r) + " tag=" + h(r.getData()));

        System.out.println();
        System.out.println(fail == 0 ? "ALL " + pass + " TESTS PASSED" : pass + " passed, " + fail + " FAILED");
        if (fail > 0) System.exit(1);
    }
}
