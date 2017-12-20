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
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.util.Collection;
import java.util.Map;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.SmbResource;
import jcifs.SmbTransport;
import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;
import jcifs.smb.SmbSessionInternal;
import jcifs.smb.SmbTransportInternal;
import jcifs.smb.SmbTreeHandleInternal;


/**
 * 
 * 
 * 
 * Compatability Notes:
 * - Windows (2k8, 2k12) servers do not like extended security + DOS error codes
 * 
 * @author mbechler
 *
 */
@RunWith ( Parameterized.class )
@SuppressWarnings ( "javadoc" )
public class SessionTest extends BaseCIFSTest {

    private static final Logger log = LoggerFactory.getLogger(SessionTest.class);


    public SessionTest ( String name, Map<String, String> properties ) {
        super(name, properties);
    }


    @Parameters ( name = "{0}" )
    public static Collection<Object> configs () {
        return getConfigs(
            "noSigning",
            "forceSigning",
            "legacyAuth",
            "forceSpnegoIntegrity",
            "noUnicode",
            "forceUnicode",
            "noNTStatus",
            "smb2",
            "smb30");
    }


    @Test
    public void logonUser () throws IOException {
        try ( SmbResource f = getDefaultShareRoot() ) {
            checkConnection(f);
            f.resolve("test").exists();
        }
    }


    @Test
    public void logonAnonymous () throws IOException {
        try ( SmbResource f = new SmbFile(getTestShareGuestURL(), withAnonymousCredentials()) ) {
            checkConnection(f);
        }
    }


    @Test
    public void logonGuest () throws IOException {
        try ( SmbResource f = new SmbFile(getTestShareGuestURL(), withTestGuestCredentials()) ) {
            checkConnection(f);
        }
    }


    @Test
    @Ignore
    public void transportReconnects () throws IOException {
        try ( SmbFile f = getDefaultShareRoot() ) {
            // transport disconnects can happen pretty much any time
            assertNotNull(f);
            f.connect();
            assertNotNull(f);
            try ( SmbTreeHandleInternal treeHandle = (SmbTreeHandleInternal) f.getTreeHandle();
                  SmbSessionInternal session = treeHandle.getSession().unwrap(SmbSessionInternal.class) ) {
                assertNotNull(session);
                try ( SmbTransportInternal transport = session.getTransport().unwrap(SmbTransportInternal.class) ) {
                    assertNotNull(transport);
                    transport.disconnect(true, true);
                    assertNotNull(f);
                    checkConnection(f);
                }
            }
        }
        catch ( Exception e ) {
            log.error("Exception", e);
            throw e;
        }
    }


    @Test
    @Ignore
    public void transportReuseSimple () throws CIFSException {
        CIFSContext ctx = withTestNTLMCredentials(getContext());
        String loc = getTestShareURL();
        try ( SmbResource f1 = ctx.get(loc) ) {
            f1.exists();
            try ( SmbResource f2 = ctx.get(loc) ) {
                f2.exists();
                connectionMatches(f1, f2);
            }
        }
    }


    @Test
    @Ignore
    public void transportReuseAnon () throws CIFSException {
        CIFSContext ctx1 = withTestNTLMCredentials(getContext());
        CIFSContext ctx2 = withAnonymousCredentials();
        String loc = getTestShareGuestURL();
        try ( SmbResource f1 = ctx1.get(loc) ) {
            f1.exists();
            try ( SmbResource f2 = ctx2.get(loc) ) {
                f2.exists();
                connectionMatches(f1, f2);
            }
        }
    }


    @Test
    @Ignore
    // BUG #14
    public void testNoLeakRequest () throws CIFSException, MalformedURLException {
        try ( SmbFile f = getDefaultShareRoot() ) {
            try ( SmbTreeHandleInternal th = (SmbTreeHandleInternal) f.getTreeHandle();
                  SmbSessionInternal sess = th.getSession().unwrap(SmbSessionInternal.class);
                  SmbTransportInternal t = (SmbTransportInternal) sess.getTransport() ) {

                assertEquals(0, t.getInflightRequests());
                f.exists();
                assertEquals(0, t.getInflightRequests());
            }
        }
    }


    @Test
    @Ignore
    // BUG #14
    public void testNoLeakRequestError () throws IOException {
        try ( SmbResource f = getDefaultShareRoot().resolve("doesnotexist") ) {
            try ( SmbTreeHandleInternal th = (SmbTreeHandleInternal) ( (SmbFile) f ).getTreeHandle();
                  SmbSessionInternal sess = th.getSession().unwrap(SmbSessionInternal.class);
                  SmbTransportInternal t = (SmbTransportInternal) sess.getTransport() ) {

                assertEquals(0, t.getInflightRequests());
                try ( InputStream is = f.openInputStream() ) {

                }
                catch ( SmbException e ) {
                    // expected
                }
                assertEquals(0, t.getInflightRequests());
            }
        }
    }


    /**
     * @param f1
     * @param f2
     * @throws CIFSException
     */
    private static void connectionMatches ( SmbResource f1, SmbResource f2 ) throws CIFSException {
        Assert.assertTrue(f1 instanceof SmbFile);
        Assert.assertTrue(f2 instanceof SmbFile);
        try ( SmbTreeHandleInternal th1 = (SmbTreeHandleInternal) ( (SmbFile) f1 ).getTreeHandle();
              SmbTreeHandleInternal th2 = (SmbTreeHandleInternal) ( (SmbFile) f2 ).getTreeHandle();
              SmbSessionInternal sess1 = th1.getSession().unwrap(SmbSessionInternal.class);
              SmbSessionInternal sess2 = th2.getSession().unwrap(SmbSessionInternal.class);
              SmbTransport t1 = sess1.getTransport();
              SmbTransport t2 = sess2.getTransport() ) {

            Assert.assertEquals(t1, t2);
        }

    }

}
