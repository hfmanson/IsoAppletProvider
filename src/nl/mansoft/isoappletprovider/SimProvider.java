package nl.mansoft.isoappletprovider;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;

public class SimProvider extends Provider {
    private SmartcardIO smartcardIO;

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
        smartcardIO = SmartcardIO.getInstance();
    }

    public static byte[] getThumbprint(X509Certificate cert)
            throws NoSuchAlgorithmException, CertificateEncodingException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] der = cert.getEncoded();
        md.update(der);
        return md.digest();
    }

    public static void testCertificates(KeyStore ks) throws KeyStoreException, NoSuchAlgorithmException, CertificateEncodingException {
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            System.out.println("alias: " + alias);
            Certificate certificate = ks.getCertificate(alias);
            X509Certificate x509 = (X509Certificate) certificate;
            byte[] thumbprint = getThumbprint(x509);
            String digestHex = Util.ByteArrayToHexString(thumbprint);
            System.out.println(digestHex);
            System.out.println(certificate.getPublicKey());
        }
    }

    public static void testSignature(Provider p, KeyStore ks, String privateKeyName) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeyException, SignatureException {
        PrivateKey privatekey = (PrivateKey) ks.getKey(privateKeyName, null);
        System.out.println(privatekey.toString());
        Signature s = Signature.getInstance("NONEwithRSA");
        s.initSign(privatekey);
        byte buf[] = new byte[] { 0x48, 0x45, 0x4e, 0x52, 0x49 };
        s.update(buf);
        byte[] signature = s.sign();
        System.out.println("signature: " + Util.ByteArrayToHexString(signature));
    }

    public static void testKeyStore() throws UnrecoverableKeyException, InvalidKeyException, SignatureException {
        try {
            Provider p = new SimProvider();
            Security.addProvider(p);
            //Util.printProviders();
            KeyStore ks = KeyStore.getInstance("SIM");
            ks.load(null, new char[] { '1', '2', '3', '4' });
            System.out.println(ks.getType());
            testCertificates(ks);
            System.out.println(ks.containsAlias("sim923"));
            System.out.println(ks.containsAlias("larie"));
            System.out.println(ks.size());
            testSignature(p, ks, "sim923");
        } catch (KeyStoreException ex) {
            Logger.getLogger(SimProvider.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(SimProvider.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(SimProvider.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(SimProvider.class.getName()).log(Level.SEVERE, null, ex);
//        } catch (UnrecoverableKeyException ex) {
//            Logger.getLogger(SimProvider.class.getName()).log(Level.SEVERE, null, ex);
//        } catch (InvalidKeyException ex) {
//            Logger.getLogger(SimProvider.class.getName()).log(Level.SEVERE, null, ex);
//        } catch (SignatureException ex) {
//            Logger.getLogger(SimProvider.class.getName()).log(Level.SEVERE, null, ex);
        }

    }
}
