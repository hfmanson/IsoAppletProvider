package nl.mansoft.isoappletprovider;

import java.security.Provider;

public class SimProvider extends Provider {
    public SimProvider() {
        super("SimProvider", 1.0, "SIM provider");
        put("SecureRandom.SIM-PRNG", "nl.mansoft.isoappletprovider.SimSecureRandom");
        put("KeyStore.SIM", "nl.mansoft.isoappletprovider.SimKeystore");
        put("Signature.NONEwithRSA", "nl.mansoft.isoappletprovider.SimSignature");
        put("Signature.NONEwithRSA SupportedKeyClasses", "nl.mansoft.isoappletprovider.SimPrivateKey");
        put("Cipher.RSA", "nl.mansoft.isoappletprovider.SimCipher");
        put("Cipher.RSA SupportedModes", "ECB");
        put("Cipher.RSA SupportedPaddings", "PKCS1PADDING");
        put("Cipher.RSA SupportedKeyClasses", "nl.mansoft.isoappletprovider.SimPrivateKey");
    }
}
