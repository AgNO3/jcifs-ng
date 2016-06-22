/*
 * © 2016 AgNO3 Gmbh & Co. KG
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
package jcifs.tests;


import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.junit.Assume;


/**
 * @author mbechler
 *
 */
public class TestConfig {

    private static final Logger log = Logger.getLogger(TestConfig.class);
    private static Properties PROPERTIES = new Properties();


    static {
        String propFile = System.getProperty("jcifs.test.properties");
        if ( propFile != null ) {
            try ( FileInputStream fis = new FileInputStream(propFile) ) {
                PROPERTIES.load(fis);
            }
            catch ( IOException e ) {
                log.error("Failed to load test properties " + propFile, e);
            }
        }
        PROPERTIES.putAll(System.getProperties());
    }


    public static Properties getProperties () {

        return PROPERTIES;
    }


    /**
     * @return
     */
    public static String getTestServer () {
        String testServer = (String) getProperties().get("test.server");
        Assume.assumeNotNull(testServer);
        return testServer;
    }


    public static String getTestUserDomain () {
        String testDomain = (String) getProperties().get("test.user.domain");
        Assume.assumeNotNull(testDomain);
        return testDomain;
    }


    public static String getTestUserPassword () {
        String testPassword = (String) getProperties().get("test.user.password");
        Assume.assumeNotNull(testPassword);
        return testPassword;
    }


    public static String getTestUser () {
        String testUser = (String) getProperties().get("test.user.name");
        Assume.assumeNotNull(testUser);
        return testUser;
    }

}
