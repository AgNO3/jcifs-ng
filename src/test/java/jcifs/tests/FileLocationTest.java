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
import jcifs.DfsReferralData;
import jcifs.SmbConstants;
import jcifs.SmbResource;
import jcifs.SmbResourceLocator;
import jcifs.config.BaseConfiguration;
import jcifs.context.BaseContext;
import jcifs.smb.SmbFile;
import jcifs.smb.SmbResourceLocatorInternal;


/**
 * @author mbechler
 *
 */
@SuppressWarnings ( "javadoc" )
public class FileLocationTest {

    @Test
    public void testRoot () throws MalformedURLException, CIFSException {
        try ( SmbResource p = new SmbFile("smb://", getContext()) ) {
            SmbResourceLocator fl = p.getLocator();
            assertNull(fl.getServer());
            assertNull(fl.getShare());
            assertEquals(SmbConstants.TYPE_WORKGROUP, fl.getType());
            assertEquals("\\", fl.getUNCPath());
            assertEquals("smb://", fl.getCanonicalURL());
            assertEquals("/", fl.getURLPath());
        }
    }


    @Test
    public void testEmpty () throws MalformedURLException, CIFSException {
        try ( SmbResource p = new SmbFile("smb:", getContext()) ) {
            SmbResourceLocator fl = p.getLocator();
            assertNull(fl.getServer());
            assertNull(fl.getShare());
            assertEquals(SmbConstants.TYPE_WORKGROUP, fl.getType());
            assertEquals("\\", fl.getUNCPath());
            assertEquals("smb://", fl.getCanonicalURL());
            assertEquals("/", fl.getURLPath());
        }
    }


    @Test
    public void testChildHost () throws MalformedURLException, CIFSException, UnknownHostException {
        try ( SmbFile p = new SmbFile("smb://", getContext());
              SmbResource c = new SmbFile(p, "1.2.3.4") ) {
            SmbResourceLocator fl = c.getLocator();
            assertEquals("1.2.3.4", fl.getServer());
            assertEquals(SmbConstants.TYPE_SERVER, fl.getType());
            assertNull(fl.getShare());
            assertEquals("\\", fl.getUNCPath());
            assertEquals("smb://1.2.3.4/", fl.getCanonicalURL());
            assertEquals("/", fl.getURLPath());
        }
    }


    @Test
    public void testChildShare () throws MalformedURLException, CIFSException, UnknownHostException {
        try ( SmbFile p = new SmbFile("smb://1.2.3.4/", getContext());
              SmbResource c = new SmbFile(p, "share/") ) {
            SmbResourceLocator fl = c.getLocator();
            assertEquals("1.2.3.4", fl.getServer());
            assertEquals(SmbConstants.TYPE_SHARE, fl.getType());
            assertEquals("share", fl.getShare());
            assertEquals("\\", fl.getUNCPath());
            assertEquals("smb://1.2.3.4/share/", fl.getCanonicalURL());
            assertEquals("/share/", fl.getURLPath());
        }
    }


    @Test
    public void testChildShareCombined () throws MalformedURLException, CIFSException, UnknownHostException {
        try ( SmbFile p = new SmbFile("smb://", getContext());
              SmbResource c = new SmbFile(p, "1.2.3.4/share/") ) {
            SmbResourceLocator fl = c.getLocator();
            assertEquals("1.2.3.4", fl.getServer());
            assertEquals(SmbConstants.TYPE_SHARE, fl.getType());
            assertEquals("share", fl.getShare());
            assertEquals("\\", fl.getUNCPath());
            assertEquals("smb://1.2.3.4/share/", fl.getCanonicalURL());
            assertEquals("/share/", fl.getURLPath());
        }
    }


    @Test
    public void testChildPath () throws MalformedURLException, CIFSException, UnknownHostException {
        try ( SmbFile p = new SmbFile("smb://1.2.3.4/share/", getContext());
              SmbResource c = new SmbFile(p, "foo/") ) {
            SmbResourceLocator fl = c.getLocator();
            assertEquals("1.2.3.4", fl.getServer());
            assertEquals(SmbConstants.TYPE_FILESYSTEM, fl.getType());
            assertEquals("share", fl.getShare());
            assertEquals("\\foo\\", fl.getUNCPath());
            assertEquals("smb://1.2.3.4/share/foo/", fl.getCanonicalURL());
            assertEquals("/share/foo/", fl.getURLPath());
        }
    }


    @Test
    public void testChildMultiPath () throws MalformedURLException, CIFSException, UnknownHostException {
        try ( SmbFile p = new SmbFile("smb://1.2.3.4/share/", getContext());
              SmbResource c = new SmbFile(p, "foo/bar/") ) {
            SmbResourceLocator fl = c.getLocator();
            assertEquals("1.2.3.4", fl.getServer());
            assertEquals(SmbConstants.TYPE_FILESYSTEM, fl.getType());
            assertEquals("share", fl.getShare());
            assertEquals("\\foo\\bar\\", fl.getUNCPath());
            assertEquals("smb://1.2.3.4/share/foo/bar/", fl.getCanonicalURL());
            assertEquals("/share/foo/bar/", fl.getURLPath());
        }
    }


    @Test
    public void testChildPathCombined () throws MalformedURLException, CIFSException, UnknownHostException {
        try ( SmbFile p = new SmbFile("smb://", getContext());
              SmbResource c = new SmbFile(p, "1.2.3.4/share/foo/") ) {
            SmbResourceLocator fl = c.getLocator();
            assertEquals("1.2.3.4", fl.getServer());
            assertEquals(SmbConstants.TYPE_FILESYSTEM, fl.getType());
            assertEquals("share", fl.getShare());
            assertEquals("\\foo\\", fl.getUNCPath());
            assertEquals("smb://1.2.3.4/share/foo/", fl.getCanonicalURL());
            assertEquals("/share/foo/", fl.getURLPath());
        }
    }


    @Test
    public void testParentRoot () throws MalformedURLException, CIFSException {
        try ( SmbFile p = new SmbFile("smb://", getContext());
              SmbResource pp = new SmbFile(p.getParent(), getContext()) ) {
            assertEquals("smb://", p.getLocator().getParent());
            assertEquals(SmbConstants.TYPE_WORKGROUP, pp.getLocator().getType());
            assertNull(pp.getLocator().getServer());
            assertNull(pp.getLocator().getShare());
        }
    }


    @Test
    public void testParentServer () throws MalformedURLException, CIFSException {
        try ( SmbFile p = new SmbFile("smb://1.2.3.4/", getContext());
              SmbResource pp = new SmbFile(p.getParent(), getContext()) ) {
            assertEquals("smb://", p.getLocator().getParent());
            SmbResourceLocator fl = pp.getLocator();
            assertEquals(SmbConstants.TYPE_WORKGROUP, fl.getType());
            assertNull(fl.getServer());
            assertNull(fl.getShare());
        }
    }


    @Test
    public void testParentShare () throws MalformedURLException, CIFSException {
        try ( SmbFile p = new SmbFile("smb://1.2.3.4/share/", getContext());
              SmbResource pp = new SmbFile(p.getParent(), getContext()) ) {
            assertEquals("smb://1.2.3.4/", p.getLocator().getParent());
            SmbResourceLocator fl = pp.getLocator();
            assertEquals(SmbConstants.TYPE_SERVER, fl.getType());
            assertEquals("1.2.3.4", fl.getServer());
            assertNull(fl.getShare());
            assertEquals("\\", fl.getUNCPath());
            assertEquals("/", fl.getURLPath());
        }
    }


    @Test
    public void testParentPath1 () throws MalformedURLException, CIFSException {
        try ( SmbFile p = new SmbFile("smb://1.2.3.4/share/foo/", getContext());
              SmbResource pp = new SmbFile(p.getParent(), getContext()) ) {
            assertEquals("smb://1.2.3.4/share/", p.getLocator().getParent());
            SmbResourceLocator fl = pp.getLocator();
            assertEquals(SmbConstants.TYPE_SHARE, fl.getType());
            assertEquals("1.2.3.4", fl.getServer());
            assertEquals("share", fl.getShare());
            assertEquals("\\", fl.getUNCPath());
            assertEquals("/share/", fl.getURLPath());
        }
    }


    @Test
    public void testParentPath2 () throws MalformedURLException, CIFSException {
        try ( SmbFile p = new SmbFile("smb://1.2.3.4/share/foo/bar/", getContext());
              SmbResource pp = new SmbFile(p.getParent(), getContext()) ) {
            assertEquals("smb://1.2.3.4/share/foo/", p.getLocator().getParent());
            SmbResourceLocator fl = pp.getLocator();
            assertEquals(SmbConstants.TYPE_FILESYSTEM, fl.getType());
            assertEquals("1.2.3.4", fl.getServer());
            assertEquals("share", fl.getShare());
            assertEquals("\\foo\\", fl.getUNCPath());
            assertEquals("/share/foo/", fl.getURLPath());
        }
    }


    @Test
    public void testDfsReferralServer () throws MalformedURLException, CIFSException {
        try ( SmbResource p = new SmbFile("smb://1.2.3.4/share/foo/bar/", getContext()) ) {
            DfsReferralData dr = new TestDfsReferral("2.3.4.5", null, "", 0);
            String reqPath = "\\foo\\bar\\";
            SmbResourceLocator fl = p.getLocator();
            assertEquals(reqPath, ( (SmbResourceLocatorInternal) fl ).handleDFSReferral(dr, reqPath));

            assertEquals("1.2.3.4", fl.getServer());
            assertEquals("2.3.4.5", fl.getServerWithDfs());
            assertEquals("share", fl.getShare());
            assertEquals("\\foo\\bar\\", fl.getUNCPath());
            assertEquals("/share/foo/bar/", fl.getURLPath());
        }
    }


    @Test
    public void testDfsReferralShare () throws MalformedURLException, CIFSException {
        try ( SmbResource p = new SmbFile("smb://1.2.3.4/share/foo/bar/", getContext()) ) {
            DfsReferralData dr = new TestDfsReferral("1.2.3.4", "other", "", 0);
            String reqPath = "\\foo\\bar\\";
            SmbResourceLocator fl = p.getLocator();
            assertEquals(reqPath, ( (SmbResourceLocatorInternal) fl ).handleDFSReferral(dr, reqPath));

            assertEquals("1.2.3.4", fl.getServer());
            assertEquals("1.2.3.4", fl.getServerWithDfs());
            assertEquals("other", fl.getShare());
            assertEquals("\\foo\\bar\\", fl.getUNCPath());
            // this intentionally sticks to the old name
            assertEquals("/share/foo/bar/", fl.getURLPath());
        }
    }


    @Test
    public void testDfsReferralShareNested () throws MalformedURLException, CIFSException {
        try ( SmbResource p = new SmbFile("smb://1.2.3.4/dfs/share/bar/", getContext()) ) {
            DfsReferralData dr = new TestDfsReferral("1.2.3.4", "target", "", 6); // consumes the /share dfs root path
            String reqPath = "\\share\\bar\\";
            SmbResourceLocator fl = p.getLocator();
            assertEquals("\\bar\\", ( (SmbResourceLocatorInternal) fl ).handleDFSReferral(dr, reqPath));
            assertEquals("1.2.3.4", fl.getServer());
            assertEquals("1.2.3.4", fl.getServerWithDfs());
            assertEquals("target", fl.getShare());
            assertEquals("\\bar\\", fl.getUNCPath());
            // this intentionally sticks to the old name
            assertEquals("/dfs/share/bar/", fl.getURLPath());
        }
    }


    @Test
    public void testDfsReferralAfterUncPath () throws MalformedURLException, CIFSException {
        try ( SmbResource p = new SmbFile("smb://1.2.3.4/share/foo/bar/", getContext()) ) {
            p.getLocator().getUNCPath();

            DfsReferralData dr = new TestDfsReferral("1.2.3.5", "other", "", 0);
            String reqPath = "\\foo\\bar\\";
            SmbResourceLocator fl = p.getLocator();
            assertEquals(reqPath, ( (SmbResourceLocatorInternal) fl ).handleDFSReferral(dr, reqPath));

            assertEquals("1.2.3.4", fl.getServer());
            assertEquals("1.2.3.5", fl.getServerWithDfs());
            assertEquals("other", fl.getShare());
            assertEquals("\\foo\\bar\\", fl.getUNCPath());
            // this intentionally sticks to the old name
            assertEquals("/share/foo/bar/", fl.getURLPath());
        }
    }


    @Test
    public void testDfsReferralChildResource () throws MalformedURLException, CIFSException {
        try ( SmbResource p = new SmbFile("smb://1.2.3.4/share/foo/", getContext()) ) {
            DfsReferralData dr = new TestDfsReferral("1.2.3.5", "other", "", 0);
            String reqPath = "\\foo\\";
            SmbResourceLocator fl = p.getLocator();
            assertEquals(reqPath, ( (SmbResourceLocatorInternal) fl ).handleDFSReferral(dr, reqPath));

            assertEquals("1.2.3.4", fl.getServer());
            assertEquals("1.2.3.5", fl.getServerWithDfs());
            assertEquals("other", fl.getShare());
            assertEquals("\\foo\\", fl.getUNCPath());
            // this intentionally sticks to the old name
            assertEquals("/share/foo/", fl.getURLPath());

            try ( SmbResource c = p.resolve("bar/") ) {
                SmbResourceLocator fl2 = c.getLocator();
                reqPath = fl2.getUNCPath();
                assertEquals(reqPath, ( (SmbResourceLocatorInternal) fl2 ).handleDFSReferral(dr, reqPath));
            }
        }
    }


    @Test
    public void testDfsReferralMultiLink () throws MalformedURLException, CIFSException {
        try ( SmbResource p = new SmbFile("smb://1.2.3.4/share/foo/", getContext()) ) {
            DfsReferralData dr = new TestDfsReferral("1.2.3.5", "otherdfs", "", 0);
            String reqPath = "\\foo\\";
            SmbResourceLocator fl = p.getLocator();
            assertEquals(reqPath, ( (SmbResourceLocatorInternal) fl ).handleDFSReferral(dr, reqPath));

            assertEquals("1.2.3.4", fl.getServer());
            assertEquals("1.2.3.5", fl.getServerWithDfs());
            assertEquals("otherdfs", fl.getShare());
            assertEquals("\\foo\\", fl.getUNCPath());
            // this intentionally sticks to the old name
            assertEquals("/share/foo/", fl.getURLPath());

            try ( SmbResource c = p.resolve("bar/") ) {
                DfsReferralData dr2 = new TestDfsReferral("1.2.3.6", "target", "", 0);
                SmbResourceLocator fl2 = c.getLocator();
                reqPath = fl2.getUNCPath();
                assertEquals(reqPath, ( (SmbResourceLocatorInternal) fl2 ).handleDFSReferral(dr2, reqPath));

                assertEquals("1.2.3.4", fl2.getServer());
                assertEquals("1.2.3.6", fl2.getServerWithDfs());
                assertEquals("target", fl2.getShare());
                assertEquals("\\foo\\bar\\", fl2.getUNCPath());
                // this intentionally sticks to the old name
                assertEquals("/share/foo/bar/", fl2.getURLPath());
            }
        }
    }


    // test case for #30
    @Test ( expected = MalformedURLException.class )
    public void testInvalid () throws MalformedURLException, CIFSException {
        try ( SmbResource p = new SmbFile("smb:a", getContext()) ) {
            p.getType();
        }
    }


    // #41
    @Test
    public void testGetName () throws MalformedURLException, CIFSException {
        try ( SmbResource p = new SmbFile("smb://MYSERVER/Public/MyVideo.mkv", getContext()) ) {

            SmbResourceLocator fl = p.getLocator();

            assertEquals("MYSERVER", fl.getServer());
            assertEquals("MYSERVER", fl.getServerWithDfs());
            assertEquals("Public", fl.getShare());
            assertEquals("\\MyVideo.mkv", fl.getUNCPath());
            assertEquals("/Public/MyVideo.mkv", fl.getURLPath());

            assertEquals("MyVideo.mkv", p.getName());
        }
    }


    // #41
    @Test
    public void testGetNameShare () throws MalformedURLException, CIFSException {
        try ( SmbResource r = new SmbFile("smb://MYSERVER/Public/", getContext());
              SmbResource p = r.resolve("MyVideo.mkv") ) {

            SmbResourceLocator fl = p.getLocator();

            assertEquals("MYSERVER", fl.getServer());
            assertEquals("MYSERVER", fl.getServerWithDfs());
            assertEquals("Public", fl.getShare());
            assertEquals("\\MyVideo.mkv", fl.getUNCPath());
            assertEquals("/Public/MyVideo.mkv", fl.getURLPath());

            assertEquals("MyVideo.mkv", p.getName());
        }
    }


    // #41
    @Test
    public void testGetNameServer () throws MalformedURLException, CIFSException {
        try ( SmbResource r = new SmbFile("smb://0.0.0.0/", getContext());
              SmbResource s = r.resolve("Public/");
              SmbResource p = s.resolve("MyVideo.mkv"); ) {

            SmbResourceLocator fl = p.getLocator();

            assertEquals("0.0.0.0", fl.getServer());
            assertEquals("0.0.0.0", fl.getServerWithDfs());
            assertEquals("Public", fl.getShare());
            assertEquals("\\MyVideo.mkv", fl.getUNCPath());
            assertEquals("/Public/MyVideo.mkv", fl.getURLPath());

            assertEquals("MyVideo.mkv", p.getName());
        }
    }


    // #87
    @Test
    public void testIPCHidden () throws MalformedURLException, CIFSException {
        try ( SmbResource r = new SmbFile("smb://0.0.0.0/IPC$/", getContext()) ) {
            assert ( r.isHidden() );
        }
    }

    private static class TestDfsReferral implements DfsReferralData {

        private String server;
        private String share;
        private String path;
        private int pathConsumed;


        /**
         * 
         */
        public TestDfsReferral ( String server, String share, String path, int pathConsumed ) {
            this.server = server;
            this.share = share;
            this.path = path;
            this.pathConsumed = pathConsumed;
        }


        /**
         * {@inheritDoc}
         *
         * @see jcifs.DfsReferralData#unwrap(java.lang.Class)
         */
        @SuppressWarnings ( "unchecked" )
        @Override
        public <T extends DfsReferralData> T unwrap ( Class<T> type ) {
            if ( type.isAssignableFrom(this.getClass()) ) {
                return (T) this;
            }
            throw new ClassCastException();
        }


        /**
         * {@inheritDoc}
         *
         * @see jcifs.DfsReferralData#getServer()
         */
        @Override
        public String getServer () {
            return this.server;
        }


        /**
         * {@inheritDoc}
         *
         * @see jcifs.DfsReferralData#getDomain()
         */
        @Override
        public String getDomain () {
            return null;
        }


        /**
         * {@inheritDoc}
         *
         * @see jcifs.DfsReferralData#getLink()
         */
        @Override
        public String getLink () {
            return null;
        }


        /**
         * {@inheritDoc}
         *
         * @see jcifs.DfsReferralData#getShare()
         */
        @Override
        public String getShare () {
            return this.share;
        }


        /**
         * {@inheritDoc}
         *
         * @see jcifs.DfsReferralData#getPathConsumed()
         */
        @Override
        public int getPathConsumed () {
            return this.pathConsumed;
        }


        /**
         * {@inheritDoc}
         *
         * @see jcifs.DfsReferralData#getPath()
         */
        @Override
        public String getPath () {
            return this.path;
        }


        /**
         * {@inheritDoc}
         *
         * @see jcifs.DfsReferralData#getExpiration()
         */
        @Override
        public long getExpiration () {
            return 0;
        }


        /**
         * {@inheritDoc}
         *
         * @see jcifs.DfsReferralData#next()
         */
        @Override
        public DfsReferralData next () {
            return this;
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
