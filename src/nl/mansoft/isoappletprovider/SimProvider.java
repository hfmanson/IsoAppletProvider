package nl.mansoft.isoappletprovider;

import java.security.Provider;

public class SimProvider extends Provider {
    public SimProvider(String arg) {
        super("SimProvider", 1.0, "PKCS11 provider");
        put("SecureRandom.SIM-PRNG", "nl.mansoft.isoappletprovider.SimSecureRandom");
        put("KeyStore." + SimKeystore.getType(), "nl.mansoft.isoappletprovider.SimKeystore");
        put("Signature.NONEwithRSA", "nl.mansoft.isoappletprovider.SimSignature");
        put("Signature.NONEwithRSA SupportedKeyClasses", "nl.mansoft.isoappletprovider.SimPrivateKey");
        put("Cipher.RSA", "nl.mansoft.isoappletprovider.SimCipher");
        put("Cipher.RSA SupportedModes", "ECB");
        put("Cipher.RSA SupportedPaddings", "PKCS1PADDING");
        put("Cipher.RSA SupportedKeyClasses", "nl.mansoft.isoappletprovider.SimPrivateKey");
        System.out.println("Sim provider, arg: " + arg);
    }

    public SimProvider() {
        this("");
    }

}
