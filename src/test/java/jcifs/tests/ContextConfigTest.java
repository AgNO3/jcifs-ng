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


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.net.URL;
import java.util.Properties;

import org.hamcrest.CoreMatchers;
import org.junit.Before;
import org.junit.Test;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.Config;
import jcifs.Credentials;
import jcifs.DialectVersion;
import jcifs.SmbResource;
import jcifs.config.PropertyConfiguration;
import jcifs.context.SingletonContext;
import jcifs.smb.NtlmPasswordAuthenticator;
import jcifs.smb.SmbFile;


/**
 * @author mbechler
 *
 */
@SuppressWarnings ( "javadoc" )
public class ContextConfigTest {

    private SingletonContext context;


    @Before
    public void setUp () {
        this.context = SingletonContext.getInstance();
    }


    @Test
    public void testSingletonInit () {
        assertNotNull(this.context.getBufferCache());
        assertNotNull(this.context.getNameServiceClient());
        assertNotNull(this.context.getTransportPool());
        assertNotNull(this.context.getUrlHandler());
        assertNotNull(this.context.getCredentials());
    }


    @Test
    public void testCredentials () {
        assertFalse(this.context.hasDefaultCredentials());
        assertNotNull(this.context.getCredentials());
    }


    @Test
    public void testFixedCredentials () {
        Credentials guestCreds = this.context.withGuestCrendentials().getCredentials();
        assertThat(guestCreds, CoreMatchers.is(CoreMatchers.instanceOf(NtlmPasswordAuthenticator.class)));
        NtlmPasswordAuthenticator ntlmGuestCreds = guestCreds.unwrap(NtlmPasswordAuthenticator.class);
        assertThat("anonymous", ntlmGuestCreds.isAnonymous(), CoreMatchers.is(false));
        assertThat("guest", ntlmGuestCreds.isGuest(), CoreMatchers.is(true));

        Credentials anonCreds = this.context.withAnonymousCredentials().getCredentials();
        assertThat(anonCreds, CoreMatchers.is(CoreMatchers.instanceOf(NtlmPasswordAuthenticator.class)));
        NtlmPasswordAuthenticator ntlmAnonCreds = anonCreds.unwrap(NtlmPasswordAuthenticator.class);
        assertEquals("", ntlmAnonCreds.getUsername());
        assertEquals("", ntlmAnonCreds.getPassword());
        assertThat("anonymous", ntlmAnonCreds.isAnonymous(), CoreMatchers.is(true));

        CIFSContext testCtx = this.context.withCredentials(new NtlmPasswordAuthenticator("TEST", "test-user", "test-pw"));
        Credentials setCreds = testCtx.getCredentials();
        assertThat(setCreds, CoreMatchers.is(CoreMatchers.instanceOf(NtlmPasswordAuthenticator.class)));
        NtlmPasswordAuthenticator setCredsNtlm = setCreds.unwrap(NtlmPasswordAuthenticator.class);
        assertEquals("TEST", setCredsNtlm.getUserDomain());
        assertEquals("test-user", setCredsNtlm.getUsername());
        assertEquals("test-pw", setCredsNtlm.getPassword());
        assertThat("anonymous", setCredsNtlm.isAnonymous(), CoreMatchers.is(false));
    }


    @Test
    public void testURLHandlerRegistration () throws IOException {
        Config.registerSmbURLHandler();
        URL u = new URL("smb://localhost/test");
        assertThat(u.openConnection(), CoreMatchers.is(CoreMatchers.instanceOf(SmbFile.class)));
    }


    @Test
    @SuppressWarnings ( "deprecation" )
    public void testLegacyURLConstructor () throws IOException {
        Config.registerSmbURLHandler();
        URL u = new URL("smb://DOMAIN;foo:bar@localhost/test");
        try ( SmbResource f = new SmbFile(u) ) {
            Credentials c = f.getContext().getCredentials();
            assertThat(c, CoreMatchers.is(CoreMatchers.instanceOf(NtlmPasswordAuthenticator.class)));
            NtlmPasswordAuthenticator ntlm = c.unwrap(NtlmPasswordAuthenticator.class);
            assertEquals("foo", ntlm.getUsername());
            assertEquals("DOMAIN", ntlm.getUserDomain());
            assertEquals("bar", ntlm.getPassword());
        }
    }


    @Test
    @SuppressWarnings ( "deprecation" )
    public void testLegacyStringConstructor () throws IOException {
        try ( SmbResource f = new SmbFile("smb://DOMAIN;foo:bar@localhost/test") ) {
            Credentials c = f.getContext().getCredentials();
            assertThat(c, CoreMatchers.is(CoreMatchers.instanceOf(NtlmPasswordAuthenticator.class)));
            NtlmPasswordAuthenticator ntlm = c.unwrap(NtlmPasswordAuthenticator.class);
            assertEquals("foo", ntlm.getUsername());
            assertEquals("DOMAIN", ntlm.getUserDomain());
            assertEquals("bar", ntlm.getPassword());
        }
    }


    @Test
    // #216
    public void testMinMaxVersions () throws CIFSException {
        Properties prop1 = new Properties();
        prop1.setProperty("jcifs.smb.client.minVersion", "SMB302");
        PropertyConfiguration p1 = new PropertyConfiguration(prop1);
        assertEquals(DialectVersion.SMB302, p1.getMinimumVersion());
        assertEquals(DialectVersion.SMB302, p1.getMaximumVersion());

        Properties prop2 = new Properties();
        prop2.setProperty("jcifs.smb.client.maxVersion", "SMB302");
        prop2.setProperty("jcifs.smb.client.minVersion", "SMB311");
        PropertyConfiguration p2 = new PropertyConfiguration(prop2);
        assertEquals(DialectVersion.SMB311, p2.getMinimumVersion());
        assertEquals(DialectVersion.SMB311, p2.getMaximumVersion());

        Properties prop3 = new Properties();
        prop3.setProperty("jcifs.smb.client.minVersion", "SMB202");
        PropertyConfiguration p3 = new PropertyConfiguration(prop3);
        assertEquals(DialectVersion.SMB202, p3.getMinimumVersion());

        // needs to be adjusted when default changes
        assertEquals(DialectVersion.SMB210, p3.getMaximumVersion());

    }


    @Test
    // #226
    public void testLegacyConfig () throws CIFSException {
        Properties prop1 = new Properties();
        prop1.setProperty("jcifs.smb.client.enableSMB2", "false");
        prop1.setProperty("jcifs.smb.client.disableSMB1", "false");
        PropertyConfiguration p1 = new PropertyConfiguration(prop1);

        assertEquals(DialectVersion.SMB1, p1.getMinimumVersion());
        assertEquals(DialectVersion.SMB1, p1.getMaximumVersion());

        Properties prop2 = new Properties();
        prop2.setProperty("jcifs.smb.client.enableSMB2", "true");
        prop2.setProperty("jcifs.smb.client.disableSMB1", "false");
        PropertyConfiguration p2 = new PropertyConfiguration(prop2);

        assertEquals(DialectVersion.SMB1, p2.getMinimumVersion());
        // needs to be adjusted when default changes
        assertEquals(DialectVersion.SMB210, p2.getMaximumVersion());

        Properties prop3 = new Properties();
        prop3.setProperty("jcifs.smb.client.enableSMB2", "true");
        prop3.setProperty("jcifs.smb.client.disableSMB1", "true");
        PropertyConfiguration p3 = new PropertyConfiguration(prop3);

        assertEquals(DialectVersion.SMB202, p3.getMinimumVersion());
    }

}
