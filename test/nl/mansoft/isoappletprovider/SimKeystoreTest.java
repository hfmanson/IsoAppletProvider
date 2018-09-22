/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package nl.mansoft.isoappletprovider;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author manson
 */
public class SimKeystoreTest {
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

    private static void printCertificates(KeyStore ks) throws KeyStoreException, NoSuchAlgorithmException, CertificateEncodingException {
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            System.out.println("alias: " + alias);
            System.out.println("********************************************************");
            Certificate certificate = ks.getCertificate(alias);
            X509Certificate x509 = (X509Certificate) certificate;
            System.out.println(x509);
            System.out.println("********************************************************");
        }
    }

    /**
     * Test of engineLoad, engineAliases, engineGetCertificate, and engineContainsAlias of class SimKeystore.
     */
    @Test
    public void testKeystore() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException    {
        Provider p = new SimProvider();
        Security.addProvider(p);
        //Util.printProviders();
        KeyStore ks = KeyStore.getInstance("SIM");
        ks.load(null, new char[] { '1', '2', '3', '4' });
        System.out.println("Keystore size: " + ks.size());
        printCertificates(ks);
        assertTrue(ks.containsAlias("sim923"));
        assertFalse(ks.containsAlias("larie"));
    }
}
