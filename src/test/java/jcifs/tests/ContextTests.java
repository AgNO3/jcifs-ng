package jcifs.tests;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;

import org.hamcrest.CoreMatchers;
import org.junit.Before;
import org.junit.Test;

import jcifs.CIFSContext;
import jcifs.Config;
import jcifs.context.SingletonContext;
import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbCredentials;
import jcifs.smb.SmbFile;


/**
 * © 2016 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 17.01.2016 by mbechler
 */

/**
 * @author mbechler
 *
 */
public class ContextTests {

    private SingletonContext context;


    @Before
    public void setup () {
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
        SmbCredentials guestCreds = this.context.withGuestCrendentials().getCredentials();
        assertThat(guestCreds, CoreMatchers.is(CoreMatchers.instanceOf(NtlmPasswordAuthentication.class)));
        NtlmPasswordAuthentication ntlmGuestCreds = (NtlmPasswordAuthentication) guestCreds;
        assertEquals("GUEST", ntlmGuestCreds.getUsername());
        assertThat("anonymous", ntlmGuestCreds.isAnonymous(), CoreMatchers.is(true));

        SmbCredentials anonCreds = this.context.withAnonymousCredentials(false).getCredentials();
        assertThat(anonCreds, CoreMatchers.is(CoreMatchers.instanceOf(NtlmPasswordAuthentication.class)));
        NtlmPasswordAuthentication ntlmAnonCreds = (NtlmPasswordAuthentication) anonCreds;
        assertEquals("", ntlmAnonCreds.getUsername());
        assertEquals("", ntlmAnonCreds.getPassword());
        assertThat("anonymous", ntlmAnonCreds.isAnonymous(), CoreMatchers.is(true));

        CIFSContext testCtx = this.context.withCredentials(new NtlmPasswordAuthentication(this.context, "TEST", "test-user", "test-pw"));
        SmbCredentials setCreds = testCtx.getCredentials();
        assertThat(setCreds, CoreMatchers.is(CoreMatchers.instanceOf(NtlmPasswordAuthentication.class)));
        NtlmPasswordAuthentication setCredsNtlm = (NtlmPasswordAuthentication) setCreds;
        assertEquals("TEST", setCredsNtlm.getUserDomain());
        assertEquals("test-user", setCredsNtlm.getUsername());
        assertEquals("test-pw", setCredsNtlm.getPassword());
        assertThat("anonymous", setCredsNtlm.isAnonymous(), CoreMatchers.is(false));
    }


    @Test
    public void testURLHandler () throws IOException {
        Config.registerSmbURLHandler();
        URL u = new URL("smb://localhost/test/");
        assertThat(u.openConnection(), CoreMatchers.is(CoreMatchers.instanceOf(SmbFile.class)));
    }


    @Test
    public void testSMB () throws IOException {
        CIFSContext ctx = withTestNTLMCredentials();
        SmbFile f = new SmbFile("smb://" + TestConfig.getTestServer() + "/test/", ctx);

        for ( SmbFile entry : f.listFiles() ) {
            System.out.println(entry);

            if ( entry.getContentLength() < 4096 ) {
                long size = 0;
                try ( InputStream is = entry.getInputStream() ) {
                    byte[] buffer = new byte[4096];
                    int read = 0;
                    while ( ( read = is.read(buffer) ) >= 0 ) {
                        size += read;
                    }
                }
                assertEquals(entry.getContentLength(), size);
            }
        }

        f = new SmbFile("smb://" + TestConfig.getTestServer() + "/test-guest/", ctx);
        f.list();

    }


    /**
     * @return
     */
    private CIFSContext withTestNTLMCredentials () {
        return this.context.withCredentials(
            new NtlmPasswordAuthentication(this.context, TestConfig.getTestUserDomain(), TestConfig.getTestUser(), TestConfig.getTestUserPassword()));
    }


    @Test
    public void testSMB2 () throws IOException {
        CIFSContext ctx = withTestNTLMCredentials();
        SmbFile f = new SmbFile("smb://" + TestConfig.getTestServer() + "/test/", ctx);
        f.length();
    }


    // @Test
    public void testPerf () throws IOException {
        long start = System.currentTimeMillis();
        SmbFile f = new SmbFile("smb://" + TestConfig.getTestServer() + "/test/100MB", withTestNTLMCredentials());

        f.length();
        byte[] buffer = new byte[0xFFFF];

        try ( InputStream is = f.getInputStream() ) {
            while ( is.read(buffer) >= 0 ) {

            }
        }

        System.out.println("100MB took " + ( System.currentTimeMillis() - start ) + " ms");
    }

}
