import javax.smartcardio.*;
import java.util.List;

public class SelTest {
    public static void main(String[] args) throws Exception {
        String aidHex = args.length > 0 ? args[0] : "F000000001DEAD02";
        byte[] aid = hex(aidHex);
        TerminalFactory tf = TerminalFactory.getDefault();
        List<CardTerminal> ts = tf.terminals().list();
        System.out.println("terminals: " + ts);
        CardTerminal t = ts.get(0);
        if (!t.isCardPresent()) { System.out.println("NO CARD"); return; }
        Card card = t.connect("*");
        System.out.println("protocol: " + card.getProtocol());
        CardChannel ch = card.getBasicChannel();
        CommandAPDU sel = new CommandAPDU(0x00, 0xA4, 0x04, 0x00, aid, 256);
        System.out.println("send: " + hex(sel.getBytes()));
        long t0 = System.nanoTime();
        try {
            ResponseAPDU r = ch.transmit(sel);
            long ms = (System.nanoTime() - t0) / 1_000_000;
            System.out.println("SW=" + String.format("%04X", r.getSW())
                + " datalen=" + r.getData().length + " elapsed_ms=" + ms);
            System.out.println("resp: " + hex(r.getBytes()));
        } catch (CardException e) {
            long ms = (System.nanoTime() - t0) / 1_000_000;
            System.out.println("CardException after " + ms + " ms: " + e);
        }
        card.disconnect(false);
    }
    static byte[] hex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++)
            b[i] = (byte) Integer.parseInt(s.substring(2*i, 2*i+2), 16);
        return b;
    }
    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02X", x));
        return sb.toString();
    }
}
