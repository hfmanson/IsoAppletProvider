package nl.mansoft.isoappletprovider;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

public class SimSignatureTest {
    public SimSignatureTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of initSign, update, and sign method, of class SimSignature.
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.KeyStoreException
     * @throws java.io.IOException
     * @throws java.security.cert.CertificateException
     * @throws java.security.UnrecoverableKeyException
     * @throws java.security.InvalidKeyException
     * @throws java.security.SignatureException
     */
    @Test
    public void testSignature() throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException, InvalidKeyException, SignatureException {
        System.out.println("testSignature");

        Provider p = new SimProvider();
        Security.addProvider(p);

        SecureRandom secureRandom = SecureRandom.getInstance("SIM-PRNG");
        byte[] random = secureRandom.generateSeed(128);

        KeyStore ks = KeyStore.getInstance("SIM");
        ks.load(null, new char[] { '1', '2', '3', '4' });
        System.out.println(ks.getType());
        PrivateKey privatekey = (PrivateKey) ks.getKey("sim923", null);
        Signature signSignature = Signature.getInstance("NONEwithRSA");
        signSignature.initSign(privatekey);
        signSignature.update(random);
        byte[] signature = signSignature.sign();
        System.out.println("signature: " + Util.ByteArrayToHexString(signature));

        Certificate sim923 = ks.getCertificate("sim923");
        Signature verifySignature = Signature.getInstance("NONEwithRSA");
        verifySignature.initVerify(sim923);
        verifySignature.update(random);
        assertTrue(verifySignature.verify(signature));
    }
}
