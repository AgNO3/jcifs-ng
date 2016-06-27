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


import java.net.MalformedURLException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Random;

import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.runners.Parameterized.Parameters;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.config.DelegatingConfiguration;
import jcifs.config.PropertyConfiguration;
import jcifs.context.BaseContext;
import jcifs.context.CIFSContextWrapper;
import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;


/**
 * @author mbechler
 *
 */
@SuppressWarnings ( "javadoc" )
public abstract class BaseCIFSTest {

    private Map<String, String> properties;
    private CIFSContext context;
    private Random rand = new Random();


    protected BaseCIFSTest ( String name, Map<String, String> properties ) {
        this.properties = properties;
    }


    /**
     * 
     * @return configuration to run
     */
    @Parameters ( name = "{0}" )
    public static Collection<Object> configs () {
        return getConfigs();
    }


    /**
     * @param mutations
     * @return
     */
    static Collection<Object> getConfigs ( String... mutations ) {
        List<Object> configs = new ArrayList<>();
        for ( Entry<String, Map<String, String>> cfg : AllTests.getConfigs(mutations).entrySet() ) {
            configs.add(new Object[] {
                cfg.getKey(), cfg.getValue()
            });
        }
        return configs;
    }


    protected static CIFSContext withConfig ( CIFSContext ctx, final DelegatingConfiguration delegatingConfiguration ) {
        return new CIFSContextWrapper(ctx) {

            @Override
            public Configuration getConfig () {
                return delegatingConfiguration;
            }
        };
    }


    @Before
    public void setUp () throws CIFSException {
        Properties props = new Properties();
        props.putAll(this.properties);
        this.context = new BaseContext(new PropertyConfiguration(props));
    }


    @After
    public void tearDown () throws CIFSException {
        this.context.close();
    }


    protected CIFSContext getContext () {
        return this.context;
    }


    protected Map<String, String> getProperties () {
        return this.properties;
    }


    protected String getRequiredProperty ( String name ) {
        String val = this.properties.get(name);
        Assume.assumeNotNull(val);
        return val;
    }


    protected CIFSContext withTestNTLMCredentials ( CIFSContext ctx ) {
        return ctx.withCredentials(new NtlmPasswordAuthentication(ctx, getTestUserDomain(), getTestUser(), getTestUserPassword()));
    }


    protected CIFSContext withTestGuestCredentials () {
        return getContext().withGuestCrendentials();
    }


    protected CIFSContext withAnonymousCredentials () {
        return getContext().withAnonymousCredentials();
    }


    protected String getTestDomain () {
        String testServer = getProperties().get(TestProperties.TEST_DOMAIN);
        Assume.assumeNotNull(testServer);
        return testServer;
    }


    protected String getTestServer () {
        String testServer = getProperties().get(TestProperties.TEST_SERVER);
        Assume.assumeNotNull(testServer);
        return testServer;
    }


    protected String getTestUserDomain () {
        return getProperties().get(TestProperties.TEST_USER_DOMAIN);

    }


    protected String getTestUserDomainRequired () {
        String testDomain = getTestUserDomain();
        Assume.assumeNotNull(testDomain);
        return testDomain;
    }


    protected String getTestUserPassword () {
        String testPassword = getProperties().get(TestProperties.TEST_USER_PASSWORD);
        Assume.assumeNotNull(testPassword);
        return testPassword;
    }


    protected String getTestUser () {
        String testUser = getProperties().get(TestProperties.TEST_USER_NAME);
        Assume.assumeNotNull(testUser);
        return testUser;
    }


    protected String getTestShareGuestURL () {
        String testGuestShare = getProperties().get(TestProperties.TEST_SHARE_GUEST);
        Assume.assumeNotNull(testGuestShare);
        return "smb://" + getTestServer() + "/" + testGuestShare + "/";
    }


    protected String getTestShareURL () {
        String testShare = getProperties().get(TestProperties.TEST_SHARE_URL_MAIN);

        if ( testShare != null ) {
            return testShare;
        }

        testShare = getProperties().get(TestProperties.TEST_SHARE_MAIN);
        if ( testShare == null ) {
            testShare = "test";
        }
        return "smb://" + getTestServer() + "/" + testShare + "/";
    }


    protected SmbFile getDefaultShareRoot () throws MalformedURLException {
        return new SmbFile(getTestShareURL(), withTestNTLMCredentials(getContext()));
    }


    protected SmbFile getDefaultShareRoot ( CIFSContext ctx ) throws MalformedURLException {
        return new SmbFile(getTestShareURL(), withTestNTLMCredentials(ctx));
    }


    protected void checkConnection ( SmbFile f ) throws SmbException {
        f.exists();
    }


    protected SmbFile createTestFile () throws MalformedURLException, UnknownHostException, SmbException {
        SmbFile f = new SmbFile(getDefaultShareRoot(), makeRandomName());
        f.createNewFile();
        return f;
    }


    protected SmbFile createTestDirectory () throws MalformedURLException, UnknownHostException, SmbException {
        SmbFile f = new SmbFile(getDefaultShareRoot(), makeRandomDirectoryName());
        f.mkdir();
        return f;
    }


    protected void cleanupTestDirectory ( SmbFile f ) throws SmbException {
        if ( f != null ) {
            f.delete();
        }
    }


    protected String makeRandomName () {
        return "jcifs-test-" + Math.abs(this.rand.nextLong());
    }


    protected String makeRandomDirectoryName () {
        return makeRandomName() + "/";
    }
}
