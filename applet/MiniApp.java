package mini;

import javacard.framework.*;

public class MiniApp extends Applet {
    public static void install(byte[] b, short o, byte l) {
        new MiniApp().register();
    }
    public void process(APDU apdu) {
        if (selectingApplet()) return;
        byte[] c = apdu.getBuffer();
        c[0] = (byte)0x42;
        apdu.setOutgoingAndSend((short)0, (short)1);
    }
}
