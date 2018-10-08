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

/**
 *
 * @author hfman
 */
public class SimSignature extends SignatureSpi{
    private final byte[] buffer;
    private int offset;
    private final SmartcardIO smartcardIO;
    private SimPrivateKey simPrivateKey;
    public SimSignature() {
        buffer = new byte[256];
        smartcardIO = SmartcardIO.getInstance(SmartcardIO.AID_ISOAPPLET);
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        simPrivateKey = (SimPrivateKey) privateKey;
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
        if (smartcardIO.manageSecurityEnvironment(simPrivateKey.getKeyReference().byteValue())) {
            signature = smartcardIO.sign(buffer, offset);
        }
        return signature;
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        throw new UnsupportedOperationException("Verify not supported.");
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
    }

    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        return null;
    }

}
