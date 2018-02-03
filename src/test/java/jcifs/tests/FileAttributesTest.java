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

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import jcifs.CIFSException;
import jcifs.SmbConstants;
import jcifs.SmbResource;
import jcifs.smb.NtStatus;
import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;
import jcifs.smb.SmbUnsupportedOperationException;
import jcifs.smb.WinError;


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
        return getConfigs("smb1", "noUnicode", "forceUnicode", "noNTStatus", "noNTSmbs", "smb2", "smb30", "smb31");
    }


    @Test
    public void testBaseFile () throws MalformedURLException, CIFSException {
        try ( SmbResource f = getDefaultShareRoot() ) {
            checkConnection(f);
            if ( f.getType() != SmbConstants.TYPE_FILESYSTEM ) {
                assertEquals(SmbConstants.TYPE_SHARE, f.getType());
            }
        }
    }


    @Test
    public void testGetFreeSpace () throws CIFSException, MalformedURLException {
        try ( SmbResource f = getDefaultShareRoot() ) {
            f.getDiskFreeSpace();
        }
    }


    public void assertCloseTime ( long timeMs ) {
        if ( timeMs - System.currentTimeMillis() > 5 * 60 * 1000L ) {
            assertTrue("Time is not within 30s, check clocks " + new Date(timeMs), false);
        }
    }


    @Test
    public void testLastModified () throws CIFSException, MalformedURLException, UnknownHostException {
        try ( SmbResource f = createTestFile() ) {
            try {
                assertCloseTime(f.lastModified());
            }
            finally {
                f.delete();
            }
        }
    }


    @Test
    public void testSetLastModified () throws CIFSException, MalformedURLException, UnknownHostException {
        try ( SmbResource f = createTestFile() ) {
            try {
                long time = System.currentTimeMillis() - 1000 * 60 * 60 * 12;
                f.setLastModified(time);

                if ( ( getContext().getConfig().getCapabilities() & SmbConstants.CAP_NT_SMBS ) == 0 ) {
                    // only have second precision
                    // there seems to be some random factor (adding one second)
                    int diff = Math.abs((int) ( ( time / 1000 ) - ( f.lastModified() / 1000 ) ));
                    Assert.assertTrue("Have set time correctly", diff < 2);
                }
                else {
                    assertEquals(time, f.lastModified());
                }
            }
            catch ( SmbUnsupportedOperationException e ) {
                Assume.assumeTrue("No Ntsmbs", false);
            }
            finally {
                f.delete();
            }
        }
    }


    @Test
    public void testCreated () throws CIFSException, MalformedURLException, UnknownHostException {
        try ( SmbResource f = createTestFile() ) {
            try {
                assertCloseTime(f.createTime());
            }
            finally {
                f.delete();
            }
        }
    }


    @Test
    public void testSetCreated () throws CIFSException, MalformedURLException, UnknownHostException {
        try ( SmbResource f = createTestFile() ) {
            try {
                long orig = f.createTime();
                long time = System.currentTimeMillis() - 60 * 60 * 12;
                f.setCreateTime(time);
                long newTime = f.createTime();
                if ( newTime == orig ) {
                    Assume.assumeTrue("Create time was not changed", false);
                }
                assertEquals(time, newTime);
            }
            catch ( SmbUnsupportedOperationException e ) {
                Assume.assumeTrue("No Ntsmbs", false);
            }
            finally {
                f.delete();
            }
        }
    }


    @Test
    public void testLastAccessed () throws CIFSException, MalformedURLException, UnknownHostException {
        try ( SmbResource f = createTestFile() ) {
            try {
                assertCloseTime(f.lastAccess());
            }
            finally {
                f.delete();
            }
        }
    }


    @Test
    public void testSetLastAccessed () throws CIFSException, MalformedURLException, UnknownHostException {
        try ( SmbResource f = createTestFile() ) {
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
    }


    @Test
    public void testSetAttributes () throws CIFSException, MalformedURLException, UnknownHostException {
        try ( SmbFile f = createTestFile() ) {
            try {
                int attrs = f.getAttributes() ^ SmbConstants.ATTR_ARCHIVE ^ SmbConstants.ATTR_HIDDEN ^ SmbConstants.ATTR_READONLY;
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
    }


    @Test
    public void testGetACL () throws IOException {
        try ( SmbFile f = getDefaultShareRoot() ) {
            try {
                jcifs.ACE[] security = f.getSecurity();
                assertNotNull(security);
            }
            catch ( SmbUnsupportedOperationException e ) {
                Assume.assumeTrue("No Ntsmbs", false);
            }
        }
    }


    @Test
    public void testGetOwner () throws IOException {
        try ( SmbFile f = getDefaultShareRoot() ) {
            try {
                jcifs.SID security = f.getOwnerUser();
                assertNotNull(security);
            }
            catch ( SmbUnsupportedOperationException e ) {
                Assume.assumeTrue("No Ntsmbs", false);
            }
        }
    }


    @Test
    public void testGetGroup () throws IOException {
        try ( SmbResource f = getDefaultShareRoot() ) {
            try {
                jcifs.SID security = f.getOwnerGroup();
                assertNotNull(security);
            }
            catch ( SmbUnsupportedOperationException e ) {
                Assume.assumeTrue("No Ntsmbs", false);
            }
        }
    }


    @Test
    public void testShareSecurity () throws IOException {
        try ( SmbResource f = getDefaultShareRoot() ) {
            try {
                jcifs.ACE[] security = f.getShareSecurity(true);
                Assume.assumeNotNull((Object) security);
            }
            catch ( SmbUnsupportedOperationException e ) {
                Assume.assumeTrue("No Ntsmbs", false);
            }
            catch ( SmbException e ) {
                if ( e.getNtStatus() == NtStatus.NT_STATUS_ACCESS_DENIED || e.getNtStatus() == WinError.ERROR_ACCESS_DENIED ) {
                    // we might not have permissions for that
                    Assume.assumeTrue("No permission for share security accesss", false);
                }
                throw e;
            }
        }
    }


    @Test
    public void testShareSize () throws IOException {
        try ( SmbResource f = getDefaultShareRoot() ) {
            long l = f.length();
            Assume.assumeTrue("No share size reported", l != 0);
        }
    }


    @Test
    public void testShareFreeSize () throws IOException {
        try ( SmbResource f = getDefaultShareRoot() ) {
            long fs = f.getDiskFreeSpace();
            Assume.assumeTrue("No free space reported", fs != 0);
        }
    }


    @Test
    public void testFileIndex () throws IOException {
        try ( SmbFile f = createTestFile() ) {
            try {
                long idx = f.fileIndex();
                Assume.assumeTrue("FileIndex unsupported", idx != 0);
            }
            finally {
                f.delete();
            }
        }
    }

}
