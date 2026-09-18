import javax.smartcardio.*;
import java.util.List;

public class ApduTest {
    public static void main(String[] args) throws Exception {
        // args[0] = AID to select; args[1..] = APDU hex strings to send in one session
        byte[] aid = hex(args[0]);
        TerminalFactory tf = TerminalFactory.getDefault();
        CardTerminal t = tf.terminals().list().get(0);
        Card card = t.connect("*");
        CardChannel ch = card.getBasicChannel();
        ResponseAPDU sel = ch.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, aid, 256));
        System.out.println("SELECT        SW=" + sw(sel) + " resp=" + hex(sel.getBytes()));
        if (sel.getSW() != 0x9000) { System.out.println("*** SELECT FAILED"); card.disconnect(false); return; }
        for (int i = 1; i < args.length; i++) {
            byte[] apdu = hex(args[i]);
            long t0 = System.nanoTime();
            try {
                ResponseAPDU r = ch.transmit(new CommandAPDU(apdu));
                long ms = (System.nanoTime() - t0) / 1_000_000;
                System.out.println("APDU[" + i + "] " + args[i].substring(0, Math.min(16, args[i].length()))
                    + ".. SW=" + sw(r) + " len=" + r.getData().length + " ms=" + ms
                    + " resp=" + hex(r.getData()));
            } catch (CardException e) {
                System.out.println("APDU[" + i + "] CardException: " + e.getMessage());
            }
        }
        card.disconnect(false);
    }
    static String sw(ResponseAPDU r) { return String.format("%04X", r.getSW()); }
    static byte[] hex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(s.substring(2*i, 2*i+2), 16);
        return b;
    }
    static String hex(byte[] b) {
        if (b == null) return "";
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02X", x));
        return sb.toString();
    }
}
