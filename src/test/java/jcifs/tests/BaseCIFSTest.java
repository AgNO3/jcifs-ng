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


import static org.junit.Assert.assertNotNull;

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
import jcifs.SmbResource;
import jcifs.config.DelegatingConfiguration;
import jcifs.config.PropertyConfiguration;
import jcifs.context.BaseContext;
import jcifs.context.CIFSContextWrapper;
import jcifs.smb.NtlmPasswordAuthenticator;
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
    private String name;


    protected BaseCIFSTest ( String name, Map<String, String> properties ) {
        this.name = name;
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

    private static final class CIFSConfigContextWrapper extends CIFSContextWrapper {

        private final DelegatingConfiguration cfg;


        CIFSConfigContextWrapper ( CIFSContext delegate, DelegatingConfiguration cfg ) {
            super(delegate);
            this.cfg = cfg;
        }


        @Override
        protected CIFSContext wrap ( CIFSContext newContext ) {
            return new CIFSConfigContextWrapper(super.wrap(newContext), this.cfg);
        }


        @Override
        public Configuration getConfig () {
            return this.cfg;
        }
    }


    protected static CIFSContext withConfig ( CIFSContext ctx, final DelegatingConfiguration cfg ) {
        return new CIFSConfigContextWrapper(ctx, cfg);
    }


    @Before
    public void setUp () throws Exception {
        Properties props = new Properties();
        props.putAll(this.properties);
        this.context = AllTests.getCachedContext(this.name, props);
    }


    @After
    public void tearDown () throws Exception {
        System.gc();
        System.gc();
        System.runFinalization();
    }


    protected CIFSContext getContext () {
        return this.context;
    }


    protected CIFSContext getNewContext () throws CIFSException {
        Properties props = new Properties();
        props.putAll(this.properties);
        return new BaseContext(new PropertyConfiguration(props));
    }


    protected Map<String, String> getProperties () {
        return this.properties;
    }


    protected String getRequiredProperty ( String prop ) {
        String val = this.properties.get(prop);
        Assume.assumeNotNull(val);
        return val;
    }


    protected CIFSContext withTestNTLMCredentials ( CIFSContext ctx ) {
        return ctx.withCredentials(new NtlmPasswordAuthenticator(getTestUserDomain(), getTestUser(), getTestUserPassword()));
    }


    protected CIFSContext withTestGuestCredentials () {
        return getContext().withGuestCrendentials();
    }


    protected CIFSContext withAnonymousCredentials () {
        return getContext().withAnonymousCredentials();
    }


    protected String getTestDomain () {
        String testDomain = getProperties().get(TestProperties.TEST_DOMAIN);
        Assume.assumeNotNull(testDomain);
        return testDomain;
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

        testShare = getTestShare();
        return "smb://" + getTestServer() + "/" + testShare + "/";
    }


    protected String getDFSRootURL () {
        String testDfsShare = getProperties().get(TestProperties.TEST_SHARE_URL_DFSROOT);
        Assume.assumeNotNull(testDfsShare);
        return testDfsShare;
    }


    protected String getTestShare () {
        String testShare;
        testShare = getProperties().get(TestProperties.TEST_SHARE_MAIN);
        if ( testShare == null ) {
            testShare = "test";
        }
        return testShare;
    }


    protected SmbFile getDefaultShareRoot () throws MalformedURLException {
        return new SmbFile(getTestShareURL(), withTestNTLMCredentials(getContext()));
    }


    protected SmbResource getDefaultShareRoot ( CIFSContext ctx ) throws MalformedURLException {
        return new SmbFile(getTestShareURL(), withTestNTLMCredentials(ctx));
    }


    protected void checkConnection ( SmbResource f ) throws CIFSException {
        assertNotNull(f);
        f.exists();
    }


    protected SmbFile createTestFile () throws MalformedURLException, UnknownHostException, CIFSException {
        try ( SmbFile defaultShareRoot = getDefaultShareRoot() ) {
            SmbFile f = new SmbFile(defaultShareRoot, makeRandomName());
            f.createNewFile();
            return f;
        }
    }


    protected SmbFile createTestDirectory () throws MalformedURLException, UnknownHostException, CIFSException {
        try ( SmbFile defaultShareRoot = getDefaultShareRoot() ) {
            SmbFile f = new SmbFile(defaultShareRoot, makeRandomDirectoryName());
            f.mkdir();
            return f;
        }
    }


    protected void cleanupTestDirectory ( SmbResource f ) throws CIFSException {
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
