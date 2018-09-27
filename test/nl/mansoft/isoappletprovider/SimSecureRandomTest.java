/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package nl.mansoft.isoappletprovider;

import java.security.SecureRandom;
import javax.smartcardio.CardException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author hfman
 */
public class SimSecureRandomTest {

    private SecureRandom secureRandom;

    public SimSecureRandomTest() {
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

    public static void printRandom(byte random[]) {
        System.out.println(Util.ByteArrayToHexString(random));
    }

    /**
     * Test of engineSetSeed method, of class SimSecureRandom.
     * @throws javax.smartcardio.CardException
     */
    @Test
    public void testEngineSetSeed() throws CardException {
        System.out.println("engineSetSeed");
        byte[] seed = null;
        SimSecureRandom instance = new SimSecureRandom();
        instance.engineSetSeed(seed);
    }

    /**
     * Test of engineNextBytes method, of class SimSecureRandom.
     * @throws javax.smartcardio.CardException
     */
    @Test
    public void testEngineNextBytes() throws CardException {
        System.out.println("engineNextBytes");
        byte[] bytes = new byte[32];
        SimSecureRandom instance = new SimSecureRandom();
        instance.engineNextBytes(bytes);
        printRandom(bytes);
    }

    /**
     * Test of engineGenerateSeed method, of class SimSecureRandom.
     * @throws javax.smartcardio.CardException
     */
    @Test
    public void testEngineGenerateSeed() throws CardException {
        System.out.println("engineGenerateSeed");
        int numBytes = 32;
        SimSecureRandom instance = new SimSecureRandom();
        byte[] result = instance.engineGenerateSeed(numBytes);
        printRandom(result);
        assertEquals(numBytes, result.length);
    }
}
