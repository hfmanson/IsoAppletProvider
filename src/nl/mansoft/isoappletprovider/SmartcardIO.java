package nl.mansoft.isoappletprovider;

import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;
import org.opensc.pkcs15.token.Token;
import org.opensc.pkcs15.token.impl.IsoAppletToken;

public class SmartcardIO {
    public final static byte[] AID_ISOAPPLET = { (byte) 0xF2, (byte) 0x76, (byte) 0xA2, (byte) 0x88, (byte) 0xBC, (byte) 0xFB, (byte) 0xA6, (byte) 0x9D, (byte) 0x34, (byte) 0xF3, (byte) 0x10, (byte) 0x01 };
    // File system related INS:
    public static final byte INS_SELECT = (byte) 0xA4;
    public static final byte INS_CREATE_FILE = (byte) 0xE0;
    public static final byte INS_UPDATE_BINARY = (byte) 0xD6;
    public static final byte INS_READ_BINARY = (byte) 0xB0;
    public static final byte INS_DELETE_FILE = (byte) 0xE4;
    // Other INS:
    public static final byte INS_VERIFY = (byte) 0x20;
    public static final byte INS_CHANGE_REFERENCE_DATA = (byte) 0x24;
    public static final byte INS_GENERATE_ASYMMETRIC_KEYPAIR = (byte) 0x46;
    public static final byte INS_RESET_RETRY_COUNTER = (byte) 0x2C;
    public static final byte INS_MANAGE_SECURITY_ENVIRONMENT = (byte) 0x22;
    public static final byte INS_PERFORM_SECURITY_OPERATION = (byte) 0x2A;
    public static final byte INS_GET_RESPONSE = (byte) 0xC0;
    public static final byte INS_PUT_DATA = (byte) 0xDB;
    public static final byte INS_GET_CHALLENGE = (byte) 0x84;
    public static final int SW_NO_ERROR = 0x9000;

    public boolean debug = false;
    private CardTerminal terminal;
    private Card card;
    private CardChannel cardChannel;
    private Token token;

    private static SmartcardIO smartcardIO;

    public void setupToken() {
        token = new IsoAppletToken(cardChannel);
    }

    public Token getToken() {
        return token;
    }

    public static SmartcardIO getInstance(byte[] aid) {
        if (smartcardIO == null) {
            try {
                smartcardIO = new SmartcardIO();
                smartcardIO.debug = true;
                String reader = System.getProperty("smartcardio.reader");
                if (reader == null) {
                    smartcardIO.setup();
                } else {
                    smartcardIO.setup(reader);
                }
                if (aid != null) {
                    CommandAPDU c = new CommandAPDU(0x00, 0xA4, 0x04, 0x00, aid);
                    ResponseAPDU responseAPDU = smartcardIO.runAPDU(c);
                    if (responseAPDU.getSW() != 0x9000) {
                        System.err.println("Error selecting: " + Util.ByteArrayToHexString(aid));
                    }
                }
                smartcardIO.setupToken();
            } catch (CardException ex) {
                Logger.getLogger(SmartcardIO.class.getName()).log(Level.SEVERE, null, ex);
                smartcardIO = null;
            }
        }
        return smartcardIO;
    }

    public static SmartcardIO getInstance() {
        return getInstance(null);
    }

    public static byte hi(int x) {
        return (byte) (x >> 8);
    }

    public static byte lo(int x) {
        return (byte) (x & 0xff);
    }

    public ResponseAPDU runAPDU(CommandAPDU c) throws CardException {
        if (debug) {
            System.out.print("command: CLA: " + Util.hex2(c.getCLA()) + ", INS: " + Util.hex2(c.getINS()) + ", P1: " + Util.hex2(c.getP1()) + ", P2: " + Util.hex2(c.getP2()));
            int nc = c.getNc();
            if (nc > 0) {
                System.out.print(", Nc: " + Util.hex2(nc) + ", data: " + Util.ByteArrayToHexString(c.getData()));
            }
            System.out.println(", Ne: " + Util.hex2(c.getNe()));
        }
        ResponseAPDU answer = cardChannel.transmit(c);
        int status = answer.getSW();
        if (status == SW_NO_ERROR) {
            byte[] data = answer.getData();
            if (debug) {
                System.out.println("answer: " + answer.toString() + ", data: " + Util.ByteArrayToHexString(data));
            }
        } else {
            System.out.println("ERROR: status: " + String.format("%04X", status));
        }
        return answer;
    }

    public boolean verify(byte[] password) {
        boolean result = false;
        try {
            ResponseAPDU responseAPDU = runAPDU(new CommandAPDU(0x00, INS_VERIFY, 0x00, 0x01, password));
            if (responseAPDU.getSW() == SW_NO_ERROR) {
                result = true;
            }
        } catch (CardException ex) {
        }
        return result;
    }

    public byte[] getChallenge(int numBytes) {
        byte[] data = null;
        try {
            ResponseAPDU responseAPDU = runAPDU(new CommandAPDU(0x00, INS_GET_CHALLENGE, 0x00, 0x00, numBytes));
            if (responseAPDU.getSW() == SW_NO_ERROR) {
                data = responseAPDU.getData();
            }
        } catch (CardException ex) {
        }
        return data;
    }

    public boolean manageSecurityEnvironment(byte keyReference) {
        boolean result = false;
        try {
            CommandAPDU commandApdu = new CommandAPDU(0x00, INS_MANAGE_SECURITY_ENVIRONMENT, 0x41, 0xb6, new byte[]{(byte) 0x80, (byte) 0x01, (byte) 0x11, (byte) 0x81, (byte) 0x02, (byte) 0x50, (byte) 0x15, (byte) 0x84, (byte) 0x01, keyReference});
            ResponseAPDU responseApdu = smartcardIO.runAPDU(commandApdu);
            result = responseApdu.getSW() == SW_NO_ERROR;
        } catch (CardException ex) {
            Logger.getLogger(SimCipher.class.getName()).log(Level.SEVERE, null, ex);
        }
        return result;
    }

    /**
     * decipher
     * @param input
     * @param inputOffset
     * @param inputLen
     * @return
    */
    public byte[] decipher(byte[] input, int inputOffset, int inputLen) {
        byte[] data = new byte[inputLen + 1];
        data[0] = 0; // padding indicator byte: "No further indication"
        System.arraycopy(input, inputOffset, data, 1, inputLen);
        byte[] decrypted = null;
        try {
            CommandAPDU commandApdu = new CommandAPDU(0x10, INS_PERFORM_SECURITY_OPERATION, 0x80, 0x86, data, 0, 0x80);
            ResponseAPDU responseApdu = runAPDU(commandApdu);
            if (responseApdu.getSW() == SW_NO_ERROR) {
                commandApdu = new CommandAPDU(0x00, INS_PERFORM_SECURITY_OPERATION, 0x80, 0x86, data, 0x80, data.length - 0x80, 0x100);
                responseApdu = runAPDU(commandApdu);
                if (responseApdu.getSW() == SW_NO_ERROR) {
                    decrypted = responseApdu.getData();
                }
            }
        } catch (CardException ex) {
            Logger.getLogger(SimCipher.class.getName()).log(Level.SEVERE, null, ex);
        }
        return decrypted;
    }

    /**
     * sign
     * @param input
     * @param inputLen
     * @return
     */
    public byte[] sign(byte[] input, int inputLen) {
        byte[] signature = null;
        try {
            CommandAPDU commandAPDU = new CommandAPDU(0x00, INS_PERFORM_SECURITY_OPERATION, 0x9E, 0x9A, input, 0, inputLen, 0x100);
            System.out.println("challenge: " + Util.ByteArrayToHexString(commandAPDU.getData()));
            ResponseAPDU responseAPDU = runAPDU(commandAPDU);
            if (responseAPDU.getSW() == SW_NO_ERROR) {
                signature = responseAPDU.getData();
            }
        } catch (CardException ex) {
            Logger.getLogger(SimCipher.class.getName()).log(Level.SEVERE, null, ex);
        }
        return signature;
    }

    public List<CardTerminal> listTerminals() throws CardException {
        // Display the list of terminals
        TerminalFactory factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals = factory.terminals().list();
        if (debug) {
            System.out.println("Terminals: " + terminals);
        }
        return terminals;
    }

    public void setup(CardTerminal terminal) throws CardException {
        this.terminal = terminal;
        //System.out.println(terminal.getName());
        //if (debug) {
            System.out.println("Waiting for card presence...");
        //}
        terminal.waitForCardPresent(0);
        // Connect wit the card
        card = terminal.connect("*");
        System.out.println("card protocol: " +  card.getProtocol());
        if (debug) {
            System.out.println("card: " + card + ", ATR: " + Util.ByteArrayToHexString(card.getATR().getBytes()));
        }
        cardChannel = card.getBasicChannel();
    }

    public void waitForCardPresent() {
        try {
            terminal.waitForCardPresent(0);
        } catch (CardException ex) {
        }
    }

    public void waitForCardAbsent() {
        try {
            terminal.waitForCardAbsent(0);
        } catch (CardException ex) {
        }
    }

    public void setup(int terminalNumber) throws CardException {
        List<CardTerminal> terminals = listTerminals();
        if (terminals.size() > terminalNumber) {
            setup(terminals.get(terminalNumber));
        } else {
            System.err.println("No terminal with number " + terminalNumber);
            System.exit(1);
        }
    }

    public void setup(String terminalName) throws CardException {
        TerminalFactory factory = TerminalFactory.getDefault();
        setup(factory.terminals().getTerminal(terminalName));
    }

    public void setup() throws CardException {
        setup(0);
    }

    public void teardown() {
        try {
            // Disconnect the card
            card.disconnect(false);
        } catch (CardException ex) {
            Logger.getLogger(SmartcardIO.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public Card getCard() {
        return card;
    }

    public ResponseAPDU selectAID(byte aid[]) throws CardException {
        return runAPDU(new CommandAPDU(0x00, INS_SELECT, 0x04, 0x00, aid));
    }

    public ResponseAPDU readBinary() throws CardException {
        return runAPDU(new CommandAPDU(0x00, INS_READ_BINARY, 0x00, 0x00, 0x100));
    }

    public ResponseAPDU updateBinary(byte data[]) throws CardException {
        return runAPDU(new CommandAPDU(0x00, INS_UPDATE_BINARY, 0x00, 0x00, data));
    }

    public ResponseAPDU readRecord(int record) throws CardException {
        return runAPDU(new CommandAPDU(0x00, 0xB2, record, 0x04, 0x100));
    }

    public void readRecords() throws CardException {
        int record = 1;
        ResponseAPDU responseAPDU;
        do {
            responseAPDU = readRecord(record++);
        } while (responseAPDU != null && responseAPDU.getSW() == SW_NO_ERROR);
    }

    public void updateRecord(int record, byte[] data) throws CardException {
        CommandAPDU c = new CommandAPDU(0x00, 0xdc, record, 0x04, data);
        runAPDU(c);
    }

    public ResponseAPDU createFile(int fid) throws CardException {
        CommandAPDU c = new CommandAPDU(0x00, 0xE0, 0x00, 0x00, new byte[] {
            0x6f,
            0x15,
                (byte) 0x81,
                0x02,
                    0x00, 0x40,
                (byte) 0x82,
                0x01,
                    0x01,
                (byte) 0x83,
                0x02,
                    hi(fid), lo(fid),
                (byte) 0x86,
                0x08,
                    (byte) 0xFF, (byte) 0x90, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x90, (byte) 0x90
        });
        return runAPDU(c);
    }
}
