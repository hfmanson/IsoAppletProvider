/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package nl.mansoft.isoappletprovider;

import static org.junit.Assert.fail;

/**
 *
 * @author hfman
 */
public class TestUtil {
    public static String getSystemProperty(String property) {
        String value = System.getProperty(property);
        if (value == null) {
            fail("System property '" + property + "' must be set");
        }
        return value;
    }
}
