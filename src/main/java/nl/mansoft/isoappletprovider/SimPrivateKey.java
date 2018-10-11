/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package nl.mansoft.isoappletprovider;

import java.math.BigInteger;
import java.security.PrivateKey;
import org.opensc.pkcs15.asn1.PKCS15PrivateKey;

/**
 *
 * @author hfman
 */
public class SimPrivateKey implements PrivateKey {
    private final PKCS15PrivateKey pkcs15PrivateKey;
    private final String algorithm;

    public SimPrivateKey(PKCS15PrivateKey pkcs15PrivateKey, String algorithm) {
        this.pkcs15PrivateKey = pkcs15PrivateKey;
        this.algorithm = algorithm;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return null;
    }

    @Override
    public String toString() {
        return pkcs15PrivateKey.getCommonObjectAttributes().getLabel();
    }

    public BigInteger getKeyReference() {
        return pkcs15PrivateKey.getCommonKeyAttributes().getKeyReference();
    }
}
