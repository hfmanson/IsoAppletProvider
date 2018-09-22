/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package nl.mansoft.isoappletprovider;

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 *
 * @author hfman
 */
public class SimSignature extends SignatureSpi{
    private byte[] buffer;
    private int offset;
    private SmartcardIO smartcardIO;
    private SimPrivateKey simPrivateKey;
    public SimSignature() throws CardException {
        buffer = new byte[256];
        smartcardIO = SmartcardIO.getInstance();
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        simPrivateKey = (SimPrivateKey) privateKey;
        System.out.println("keyref: " + simPrivateKey.getKeyReference());
        offset = 0;
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        if (offset == buffer.length) {
            throw new SignatureException("buffer full");
        } else {
            buffer[offset++] = b;
        }
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        if (offset + len >= buffer.length) {
            throw new SignatureException("buffer full");
        } else {
            System.arraycopy(b, off, buffer, offset, len);
            offset += len;
        }
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        byte[] signature = null;
        try {
            CommandAPDU commandAPDU = new CommandAPDU(0x00, 0x22, 0x41, 0xb6, new byte[] { (byte) 0x80, (byte) 0x01, (byte) 0x11, (byte) 0x81, (byte) 0x02, (byte) 0x50, (byte) 0x15, (byte) 0x84, (byte) 0x01, simPrivateKey.getKeyReference().byteValue()});
            ResponseAPDU responseAPDU = smartcardIO.runAPDU(commandAPDU);
            if (responseAPDU.getSW() == 0x9000) {
                commandAPDU = new CommandAPDU(0x00, 0x2A, 0x9E, 0x9A, buffer, 0, offset, 0x100);
                System.out.println("challenge: " + Util.ByteArrayToHexString(commandAPDU.getData()));
                responseAPDU = smartcardIO.runAPDU(commandAPDU);
                if (responseAPDU.getSW() == 0x9000) {
                    signature = responseAPDU.getData();
                }
            }
        } catch (CardException ex) {
            Logger.getLogger(SimSignature.class.getName()).log(Level.SEVERE, null, ex);
        }
        return signature;
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        return true;
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
    }

    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        return null;
    }

}
