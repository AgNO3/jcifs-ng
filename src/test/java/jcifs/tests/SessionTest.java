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

import java.io.IOException;
import java.util.Collection;
import java.util.Map;

import org.apache.log4j.Logger;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import jcifs.smb.SmbFile;
import jcifs.smb.SmbSession;
import jcifs.smb.SmbTransport;
import jcifs.smb.SmbTreeHandleImpl;


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

    public SessionTest ( String name, Map<String, String> properties ) {
        super(name, properties);
    }


    @Parameters ( name = "{0}" )
    public static Collection<Object> configs () {
        return getConfigs("noSigning", "forceSigning", "legacyAuth", "noUnicode", "forceUnicode", "noNTStatus");
    }


    @Test
    public void logonUser () throws IOException {
        SmbFile f = getDefaultShareRoot();
        checkConnection(f);
    }


    @Test
    public void logonAnonymous () throws IOException {
        SmbFile f = new SmbFile(getTestShareGuestURL(), withAnonymousCredentials());
        checkConnection(f);
    }


    @Test
    public void logonGuest () throws IOException {
        SmbFile f = new SmbFile(getTestShareGuestURL(), withTestGuestCredentials());
        checkConnection(f);
    }


    @Test
    public void transportReconnects () throws IOException {
        try {
            // transport disconnects can happen pretty much any time
            SmbFile f = getDefaultShareRoot();
            assertNotNull(f);
            f.connect();
            assertNotNull(f);
            SmbSession session = ( (SmbTreeHandleImpl) f.getTreeHandle() ).getSession();
            assertNotNull(session);
            SmbTransport transport = session.getTransport();
            assertNotNull(transport);
            transport.disconnect(true);
            assertNotNull(f);
            checkConnection(f);
        }
        catch ( Exception e ) {
            Logger.getLogger(SessionTest.class).error("Exception", e);
            throw e;
        }
    }

}
