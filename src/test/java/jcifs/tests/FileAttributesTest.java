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
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.UnknownHostException;
import java.util.Collection;
import java.util.Date;
import java.util.Map;

import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import jcifs.smb.ACE;
import jcifs.smb.SID;
import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;
import jcifs.smb.SmbUnsupportedOperationException;


/**
 * 
 * 
 * 
 * @author mbechler
 */
@RunWith ( Parameterized.class )
@SuppressWarnings ( "javadoc" )
public class FileAttributesTest extends BaseCIFSTest {

    public FileAttributesTest ( String name, Map<String, String> properties ) {
        super(name, properties);
    }


    @Parameters ( name = "{0}" )
    public static Collection<Object> configs () {
        return getConfigs("noUnicode", "forceUnicode", "noNTStatus", "noNTSmbs");
    }


    @Test
    public void testBaseFile () throws MalformedURLException, SmbException {
        SmbFile f = getDefaultShareRoot();
        checkConnection(f);
        if ( f.getType() != SmbFile.TYPE_FILESYSTEM ) {
            assertEquals(SmbFile.TYPE_SHARE, f.getType());
        }
    }


    @Test
    public void testGetFreeSpace () throws SmbException, MalformedURLException {
        SmbFile f = getDefaultShareRoot();
        f.getDiskFreeSpace();
    }


    public void assertCloseTime ( long timeMs ) {
        if ( timeMs - System.currentTimeMillis() > 5 * 60 * 1000L ) {
            assertTrue("Time is not within 30s, check clocks " + new Date(timeMs), false);
        }
    }


    @Test
    public void testLastModified () throws SmbException, MalformedURLException, UnknownHostException {
        SmbFile f = createTestFile();
        try {
            assertCloseTime(f.lastModified());
        }
        finally {
            f.delete();
        }
    }


    @Test
    public void testSetLastModified () throws SmbException, MalformedURLException, UnknownHostException {
        SmbFile f = createTestFile();
        try {
            long time = System.currentTimeMillis() - 60 * 60 * 12;
            f.setLastModified(time);
            assertEquals(time, f.lastModified());
        }
        catch ( SmbUnsupportedOperationException e ) {
            Assume.assumeTrue("No Ntsmbs", false);
        }
        finally {
            f.delete();
        }
    }


    @Test
    public void testCreated () throws SmbException, MalformedURLException, UnknownHostException {
        SmbFile f = createTestFile();
        try {
            assertCloseTime(f.createTime());
        }
        finally {
            f.delete();
        }
    }


    @Test
    public void testSetCreated () throws SmbException, MalformedURLException, UnknownHostException {
        SmbFile f = createTestFile();
        try {
            long time = System.currentTimeMillis() - 60 * 60 * 12;
            f.setCreateTime(time);
            assertEquals(time, f.createTime());
        }
        catch ( SmbUnsupportedOperationException e ) {
            Assume.assumeTrue("No Ntsmbs", false);
        }
        finally {
            f.delete();
        }
    }


    @Test
    public void testLastAccessed () throws SmbException, MalformedURLException, UnknownHostException {
        SmbFile f = createTestFile();
        try {
            assertCloseTime(f.lastAccess());
        }
        finally {
            f.delete();
        }
    }


    @Test
    public void testSetLastAccessed () throws SmbException, MalformedURLException, UnknownHostException {
        SmbFile f = createTestFile();
        try {
            long time = System.currentTimeMillis() - 60 * 60 * 12;
            f.setLastAccess(time);
            assertEquals(time, f.lastAccess());
        }
        catch ( SmbUnsupportedOperationException e ) {
            Assume.assumeTrue("No Ntsmbs", false);
        }
        finally {
            f.delete();
        }
    }


    @Test
    public void testSetAttributes () throws SmbException, MalformedURLException, UnknownHostException {
        SmbFile f = createTestFile();
        try {
            int attrs = f.getAttributes() ^ SmbFile.ATTR_ARCHIVE ^ SmbFile.ATTR_HIDDEN ^ SmbFile.ATTR_READONLY;
            f.setAttributes(attrs);
            assertEquals(attrs, f.getAttributes());
        }
        catch ( SmbUnsupportedOperationException e ) {
            Assume.assumeTrue("No Ntsmbs", false);
        }
        finally {
            f.delete();
        }
    }


    @Test
    public void testGetACL () throws IOException {
        SmbFile f = getDefaultShareRoot();
        try {
            ACE[] security = f.getSecurity();
            assertNotNull(security);
        }
        catch ( SmbUnsupportedOperationException e ) {
            Assume.assumeTrue("No Ntsmbs", false);
        }
    }


    @Test
    public void testGetOwner () throws IOException {
        SmbFile f = getDefaultShareRoot();
        try {
            SID security = f.getOwnerUser();
            assertNotNull(security);
        }
        catch ( SmbUnsupportedOperationException e ) {
            Assume.assumeTrue("No Ntsmbs", false);
        }
    }


    @Test
    public void testGetGroup () throws IOException {
        SmbFile f = getDefaultShareRoot();
        try {
            SID security = f.getOwnerGroup();
            assertNotNull(security);
        }
        catch ( SmbUnsupportedOperationException e ) {
            Assume.assumeTrue("No Ntsmbs", false);
        }

    }

}
