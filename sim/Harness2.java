import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class Harness2 {
    static String h(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02X", x));
        return s.toString();
    }

    public static void main(String[] args) {
        try {
            CardSimulator sim = new CardSimulator();
            byte[] aidBytes = new byte[]{(byte)0xF0,0x00,0x00,0x00,0x01,(byte)0xDE,(byte)0xAD,0x01};

            // 1) virgin card: SELECT our AID -> expect 6A82
            ResponseAPDU r = sim.transmitCommand(new CommandAPDU(0x00, (byte)0xA4, 0x04, 0x00, aidBytes));
            System.out.println("1) SELECT before install : SW=" + String.format("%04X", r.getSW()));

            // 2) install + select
            AID aid = AIDUtil.create(aidBytes);
            sim.installApplet(aid, CollarMAC_SIM2.class);
            boolean ok = sim.selectApplet(aid);
            System.out.println("2) install+select          : " + ok);

            // 3) wrong INS -> expect 6D00
            r = sim.transmitCommand(new CommandAPDU((byte)0x80, (byte)0x99, 0x00, 0x00));
            System.out.println("3) INS 0x99              : SW=" + String.format("%04X", r.getSW()));

            // 4) wrong CLA -> expect 6E00 (SW_CLA_NOT_SUPPORTED)
            r = sim.transmitCommand(new CommandAPDU(0x00, 0x32, 0x00, 0x00, new byte[8]));
            System.out.println("4) CLA 0x00              : SW=" + String.format("%04X", r.getSW()));

            // 5) the MAC: challenge from the article
            byte[] ch = new byte[]{0x51,0x42,0x43,0x44,0x45,0x46,0x47,0x48};
            r = sim.transmitCommand(new CommandAPDU((byte)0x80, 0x32, 0x00, 0x00, ch));
            System.out.println("5) MAC (key = zeros)     : SW=" + String.format("%04X", r.getSW())
                    + "  CMAC=" + h(r.getData()) + "  len=" + r.getData().length);
        } catch (Exception e) {
            System.out.println("EXCEPTION: " + e.getClass().getName() + ": " + e.getMessage());
        }
    }
}
