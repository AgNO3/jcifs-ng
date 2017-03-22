/*
 * © 2017 AgNO3 Gmbh & Co. KG
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
import static org.junit.Assert.assertNull;

import java.net.MalformedURLException;
import java.net.UnknownHostException;

import org.junit.Test;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.config.BaseConfiguration;
import jcifs.context.BaseContext;
import jcifs.smb.DfsReferral;
import jcifs.smb.SmbFile;
import jcifs.smb.SmbFileLocator;


/**
 * @author mbechler
 *
 */
@SuppressWarnings ( "javadoc" )
public class FileLocationTest {

    @Test
    public void testRoot () throws MalformedURLException, CIFSException {
        try ( SmbFile p = new SmbFile("smb://", getContext()) ) {
            SmbFileLocator fl = p.getFileLocator();
            assertNull(fl.getServer());
            assertNull(fl.getShare());
            assertEquals(SmbFile.TYPE_WORKGROUP, fl.getType());
            assertEquals("\\", fl.getUNCPath());
            assertEquals("smb://", fl.getCanonicalURL());
            assertEquals("/", fl.getURLPath());
        }
    }


    @Test
    public void testChildHost () throws MalformedURLException, CIFSException, UnknownHostException {
        try ( SmbFile p = new SmbFile("smb://", getContext());
              SmbFile c = new SmbFile(p, "1.2.3.4") ) {
            SmbFileLocator fl = c.getFileLocator();
            assertEquals("1.2.3.4", fl.getServer());
            assertEquals(SmbFile.TYPE_SERVER, fl.getType());
            assertNull(fl.getShare());
            assertEquals("\\", fl.getUNCPath());
            assertEquals("smb://1.2.3.4/", fl.getCanonicalURL());
            assertEquals("/", fl.getURLPath());
        }
    }


    @Test
    public void testChildShare () throws MalformedURLException, CIFSException, UnknownHostException {
        try ( SmbFile p = new SmbFile("smb://1.2.3.4/", getContext());
              SmbFile c = new SmbFile(p, "share/") ) {
            SmbFileLocator fl = c.getFileLocator();
            assertEquals("1.2.3.4", fl.getServer());
            assertEquals(SmbFile.TYPE_SHARE, fl.getType());
            assertEquals("share", fl.getShare());
            assertEquals("\\", fl.getUNCPath());
            assertEquals("smb://1.2.3.4/share", fl.getCanonicalURL());
            assertEquals("/share", fl.getURLPath());
        }
    }


    @Test
    public void testChildShareCombined () throws MalformedURLException, CIFSException, UnknownHostException {
        try ( SmbFile p = new SmbFile("smb://", getContext());
              SmbFile c = new SmbFile(p, "1.2.3.4/share/") ) {
            SmbFileLocator fl = c.getFileLocator();
            assertEquals("1.2.3.4", fl.getServer());
            assertEquals(SmbFile.TYPE_SHARE, fl.getType());
            assertEquals("share", fl.getShare());
            assertEquals("\\", fl.getUNCPath());
            assertEquals("smb://1.2.3.4/share", fl.getCanonicalURL());
            assertEquals("/share", fl.getURLPath());
        }
    }


    @Test
    public void testChildPath () throws MalformedURLException, CIFSException, UnknownHostException {
        try ( SmbFile p = new SmbFile("smb://1.2.3.4/share/", getContext());
              SmbFile c = new SmbFile(p, "foo/") ) {
            SmbFileLocator fl = c.getFileLocator();
            assertEquals("1.2.3.4", fl.getServer());
            assertEquals(SmbFile.TYPE_FILESYSTEM, fl.getType());
            assertEquals("share", fl.getShare());
            assertEquals("\\foo", fl.getUNCPath());
            assertEquals("smb://1.2.3.4/share/foo", fl.getCanonicalURL());
            assertEquals("/share/foo", fl.getURLPath());
        }
    }


    @Test
    public void testChildMultiPath () throws MalformedURLException, CIFSException, UnknownHostException {
        try ( SmbFile p = new SmbFile("smb://1.2.3.4/share/", getContext());
              SmbFile c = new SmbFile(p, "foo/bar/") ) {
            SmbFileLocator fl = c.getFileLocator();
            assertEquals("1.2.3.4", fl.getServer());
            assertEquals(SmbFile.TYPE_FILESYSTEM, fl.getType());
            assertEquals("share", fl.getShare());
            assertEquals("\\foo\\bar", fl.getUNCPath());
            assertEquals("smb://1.2.3.4/share/foo/bar", fl.getCanonicalURL());
            assertEquals("/share/foo/bar", fl.getURLPath());
        }
    }


    @Test
    public void testChildPathCombined () throws MalformedURLException, CIFSException, UnknownHostException {
        try ( SmbFile p = new SmbFile("smb://", getContext());
              SmbFile c = new SmbFile(p, "1.2.3.4/share/foo/") ) {
            SmbFileLocator fl = c.getFileLocator();
            assertEquals("1.2.3.4", fl.getServer());
            assertEquals(SmbFile.TYPE_FILESYSTEM, fl.getType());
            assertEquals("share", fl.getShare());
            assertEquals("\\foo", fl.getUNCPath());
            assertEquals("smb://1.2.3.4/share/foo", fl.getCanonicalURL());
            assertEquals("/share/foo", fl.getURLPath());
        }
    }


    @Test
    public void testParentRoot () throws MalformedURLException, CIFSException {
        try ( SmbFile p = new SmbFile("smb://", getContext());
              SmbFile pp = new SmbFile(p.getParent(), getContext()) ) {
            assertEquals("smb://", p.getFileLocator().getParent());
            assertEquals(SmbFile.TYPE_WORKGROUP, pp.getFileLocator().getType());
            assertNull(pp.getFileLocator().getServer());
            assertNull(pp.getFileLocator().getShare());
        }
    }


    @Test
    public void testParentServer () throws MalformedURLException, CIFSException {
        try ( SmbFile p = new SmbFile("smb://1.2.3.4/", getContext());
              SmbFile pp = new SmbFile(p.getParent(), getContext()) ) {
            assertEquals("smb://", p.getFileLocator().getParent());
            SmbFileLocator fl = pp.getFileLocator();
            assertEquals(SmbFile.TYPE_WORKGROUP, fl.getType());
            assertNull(fl.getServer());
            assertNull(fl.getShare());
        }
    }


    @Test
    public void testParentShare () throws MalformedURLException, CIFSException {
        try ( SmbFile p = new SmbFile("smb://1.2.3.4/share/", getContext());
              SmbFile pp = new SmbFile(p.getParent(), getContext()) ) {
            assertEquals("smb://1.2.3.4/", p.getFileLocator().getParent());
            SmbFileLocator fl = pp.getFileLocator();
            assertEquals(SmbFile.TYPE_SERVER, fl.getType());
            assertEquals("1.2.3.4", fl.getServer());
            assertNull(fl.getShare());
            assertEquals("\\", fl.getUNCPath());
            assertEquals("/", fl.getURLPath());
        }
    }


    @Test
    public void testParentPath1 () throws MalformedURLException, CIFSException {
        try ( SmbFile p = new SmbFile("smb://1.2.3.4/share/foo/", getContext());
              SmbFile pp = new SmbFile(p.getParent(), getContext()) ) {
            assertEquals("smb://1.2.3.4/share/", p.getFileLocator().getParent());
            SmbFileLocator fl = pp.getFileLocator();
            assertEquals(SmbFile.TYPE_SHARE, fl.getType());
            assertEquals("1.2.3.4", fl.getServer());
            assertEquals("share", fl.getShare());
            assertEquals("\\", fl.getUNCPath());
            assertEquals("/share/", fl.getURLPath());
        }
    }


    @Test
    public void testParentPath2 () throws MalformedURLException, CIFSException {
        try ( SmbFile p = new SmbFile("smb://1.2.3.4/share/foo/bar/", getContext());
              SmbFile pp = new SmbFile(p.getParent(), getContext()) ) {
            assertEquals("smb://1.2.3.4/share/foo/", p.getFileLocator().getParent());
            SmbFileLocator fl = pp.getFileLocator();
            assertEquals(SmbFile.TYPE_FILESYSTEM, fl.getType());
            assertEquals("1.2.3.4", fl.getServer());
            assertEquals("share", fl.getShare());
            assertEquals("\\foo", fl.getUNCPath());
            assertEquals("/share/foo/", fl.getURLPath());
        }
    }


    @Test
    public void testDfsReferralServer () throws MalformedURLException, CIFSException {
        try ( SmbFile p = new SmbFile("smb://1.2.3.4/share/foo/bar/", getContext()) ) {
            DfsReferral dr = new DfsReferral();
            dr.server = "2.3.4.5";
            dr.path = "";
            String reqPath = "\\foo\\bar\\";
            SmbFileLocator fl = p.getFileLocator();
            assertEquals(reqPath, fl.handleDFSReferral(dr, reqPath));

            assertEquals("1.2.3.4", fl.getServer());
            assertEquals("2.3.4.5", fl.getServerWithDfs());
            assertEquals("share", fl.getShare());
            assertEquals("\\foo\\bar", fl.getUNCPath());
            assertEquals("/share/foo/bar/", fl.getURLPath());
        }
    }


    @Test
    public void testDfsReferralShare () throws MalformedURLException, CIFSException {
        try ( SmbFile p = new SmbFile("smb://1.2.3.4/share/foo/bar/", getContext()) ) {
            DfsReferral dr = new DfsReferral();
            dr.server = "1.2.3.4";
            dr.share = "other";
            dr.path = "";
            String reqPath = "\\foo\\bar\\";
            SmbFileLocator fl = p.getFileLocator();
            assertEquals(reqPath, fl.handleDFSReferral(dr, reqPath));

            assertEquals("1.2.3.4", fl.getServer());
            assertEquals("1.2.3.4", fl.getServerWithDfs());
            assertEquals("other", fl.getShare());
            assertEquals("\\foo\\bar", fl.getUNCPath());
            // this intentionally sticks to the old name
            assertEquals("/share/foo/bar/", fl.getURLPath());
        }
    }


    @Test
    public void testDfsReferralShareNested () throws MalformedURLException, CIFSException {
        try ( SmbFile p = new SmbFile("smb://1.2.3.4/dfs/share/bar/", getContext()) ) {
            DfsReferral dr = new DfsReferral();
            dr.server = "1.2.3.4";
            dr.share = "target";
            dr.pathConsumed = 6; // consumes the /share dfs root path
            dr.path = "";
            String reqPath = "\\share\\bar\\";
            SmbFileLocator fl = p.getFileLocator();
            assertEquals("\\bar\\", fl.handleDFSReferral(dr, reqPath));
            assertEquals("1.2.3.4", fl.getServer());
            assertEquals("1.2.3.4", fl.getServerWithDfs());
            assertEquals("target", fl.getShare());
            assertEquals("\\bar", fl.getUNCPath());
            // this intentionally sticks to the old name
            assertEquals("/dfs/share/bar/", fl.getURLPath());
        }
    }


    /**
     * @return
     * @throws CIFSException
     */
    private static CIFSContext getContext () throws CIFSException {
        return new BaseContext(new BaseConfiguration(true));
    }
}
