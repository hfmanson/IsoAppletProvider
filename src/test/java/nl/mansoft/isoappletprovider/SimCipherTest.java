package nl.mansoft.isoappletprovider;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.smartcardio.CardException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

public class SimCipherTest {
    public SimCipherTest() {
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
     * Test of doFinal method, of class SimCipher.
     * @throws javax.smartcardio.CardException
     */
    @Test
    public void testDecrypt() throws CardException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        System.out.println("testDecrypt");
        String alias = TestUtil.getSystemProperty("nl.mansoft.isoappletprovider.alias");
        if (alias != null) {
            Provider p = new SimProvider();
            Security.addProvider(p);

            SecureRandom secureRandom = SecureRandom.getInstance("SIM-PRNG");
            byte[] random = secureRandom.generateSeed(128);

            KeyStore ks = KeyStore.getInstance(SimKeystore.getType());
            ks.load(null, new char[] { '1', '2', '3', '4' });
            System.out.println(ks.getType());


            Certificate sim923 = ks.getCertificate(alias);
            PublicKey pubkey = sim923.getPublicKey();
            String algorithm = pubkey.getAlgorithm();
            System.out.println("Public key algorithm: " + algorithm);
            Cipher encryptCipher = Cipher.getInstance(algorithm);
            encryptCipher.init(Cipher.ENCRYPT_MODE, pubkey);
            byte[] encrypted = encryptCipher.doFinal(random);

            PrivateKey privatekey = (PrivateKey) ks.getKey(alias, null);
            algorithm = privatekey.getAlgorithm();
            System.out.println("Private key algorithm: " + algorithm);
            Cipher decryptCipher = Cipher.getInstance(algorithm, p);
            decryptCipher.init(Cipher.DECRYPT_MODE, privatekey);
            byte[] decrypted = decryptCipher.doFinal(encrypted);

            assertArrayEquals(decrypted, random);
        }
    }
}
