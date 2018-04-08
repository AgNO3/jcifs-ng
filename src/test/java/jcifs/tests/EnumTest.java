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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.CloseableIterator;
import jcifs.ResolverType;
import jcifs.SmbConstants;
import jcifs.SmbResource;
import jcifs.SmbTreeHandle;
import jcifs.config.DelegatingConfiguration;
import jcifs.context.CIFSContextWrapper;
import jcifs.netbios.NameServiceClientImpl;
import jcifs.smb.DosFileFilter;
import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;
import jcifs.smb.SmbFilenameFilter;
import jcifs.smb.SmbUnsupportedOperationException;


/**
 * @author mbechler
 *
 */
@RunWith ( Parameterized.class )
@SuppressWarnings ( "javadoc" )
public class EnumTest extends BaseCIFSTest {

    private static final Logger log = LoggerFactory.getLogger(EnumTest.class);


    /**
     * @param name
     * @param properties
     */
    public EnumTest ( String name, Map<String, String> properties ) {
        super(name, properties);
    }


    @Parameters ( name = "{0}" )
    public static Collection<Object> configs () {
        return getConfigs("smb1", "noUnicode", "forceUnicode", "noNTStatus", "noNTSmbs", "smb2", "smb30", "smb31");
    }


    @Ignore ( "This causes a connection to whatever local master browser is available, config may be incompatible with it" )
    @Test
    public void testBrowse () throws MalformedURLException, CIFSException {
        CIFSContext ctx = withAnonymousCredentials();
        try ( SmbFile smbFile = new SmbFile("smb://", ctx) ) {
            try ( CloseableIterator<SmbResource> it = smbFile.children() ) {
                while ( it.hasNext() ) {
                    try ( SmbResource serv = it.next() ) {
                        System.err.println(serv.getName());
                    }
                }
            }
        }
        catch ( SmbUnsupportedOperationException e ) {
            Assume.assumeTrue("Browsing unsupported", false);
        }
    }


    @Test
    public void testBrowseDomain () throws MalformedURLException, CIFSException {
        CIFSContext ctx = withAnonymousCredentials();
        try ( SmbFile smbFile = new SmbFile("smb://" + getRequiredProperty(TestProperties.TEST_DOMAIN_SHORT), ctx) ) {
            // if domain is resolved through DNS this will be treated as a server and will enumerate shares instead
            Assume.assumeTrue("Not workgroup", SmbConstants.TYPE_WORKGROUP == smbFile.getType());
            try ( CloseableIterator<SmbResource> it = smbFile.children() ) {
                while ( it.hasNext() ) {
                    try ( SmbResource serv = it.next() ) {
                        System.err.println(serv.getName());
                        assertEquals(SmbConstants.TYPE_SERVER, serv.getType());
                        assertTrue(serv.isDirectory());
                    }
                }
            }
        }
        catch ( SmbUnsupportedOperationException e ) {
            Assume.assumeTrue("Browsing unsupported", false);
        }
    }


    @Test
    public void testBrowseDomainNetbios () throws MalformedURLException, CIFSException {

        // only do this if a WINS server is enabled
        getRequiredProperty("jcifs.netbios.wins");

        CIFSContext bctx = withAnonymousCredentials();

        // ensure that the domain name gets resolved through WINS so that
        // it gets the workgroup type.
        CIFSContext ctx = withConfig(bctx, new DelegatingConfiguration(bctx.getConfig()) {

            @Override
            public List<ResolverType> getResolveOrder () {
                return Arrays.asList(ResolverType.RESOLVER_WINS);
            }
        });

        // need to override NameServiceClient as it otherwise gets initialized with the original config
        final NameServiceClientImpl nsc = new NameServiceClientImpl(ctx);
        ctx = new CIFSContextWrapper(ctx) {

            @Override
            public jcifs.NameServiceClient getNameServiceClient () {
                return nsc;
            }
        };

        try ( SmbFile smbFile = new SmbFile("smb://" + getRequiredProperty(TestProperties.TEST_DOMAIN_SHORT), ctx) ) {
            // if domain is resolved through DNS this will be treated as a server and will enumerate shares instead
            Assume.assumeTrue("Not workgroup", SmbConstants.TYPE_WORKGROUP == smbFile.getType());
            try ( CloseableIterator<SmbResource> it = smbFile.children() ) {
                while ( it.hasNext() ) {
                    try ( SmbResource serv = it.next() ) {
                        System.err.println(serv.getName());
                        assertEquals(SmbConstants.TYPE_SERVER, serv.getType());
                        assertTrue(serv.isDirectory());
                    }
                }
            }
        }
        catch ( SmbUnsupportedOperationException e ) {
            Assume.assumeTrue("Browsing unsupported", false);
        }
    }


    @Test
    public void testShareEnum () throws MalformedURLException, CIFSException {
        try ( SmbFile smbFile = new SmbFile("smb://" + getTestServer(), withTestNTLMCredentials(getContext())) ) {
            String[] list = smbFile.list();
            assertNotNull(list);
            assertTrue("No share found", list.length > 0);
            log.debug(Arrays.toString(list));
        }
    }


    @Test
    public void testDomainShareEnum () throws MalformedURLException, CIFSException {
        try ( SmbFile smbFile = new SmbFile("smb://" + getTestDomain(), withTestNTLMCredentials(getContext())) ) {
            String[] list = smbFile.list();
            assertNotNull(list);
            assertTrue("No share found", list.length > 0);
            log.debug(Arrays.toString(list));
        }
    }


    @Test
    public void testDFSShareEnum () throws CIFSException, MalformedURLException {
        String dfsRoot = getDFSRootURL();
        try ( SmbFile smbFile = new SmbFile(dfsRoot, withTestNTLMCredentials(getContext())) ) {
            String[] list = smbFile.list();
            assertNotNull(list);
            assertTrue("No share found", list.length > 0);
            log.debug(Arrays.toString(list));

            String shareUrl = getTestShareURL();
            String link = shareUrl.substring(dfsRoot.length());

            Set<String> listLinks = new HashSet<>(Arrays.asList(list));
            int firstSep = link.indexOf('/');
            if ( firstSep == link.length() - 1 ) {
                // single level
                assertTrue("Link not found " + link, listLinks.contains(link));
            }
            else {
                link = link.substring(0, firstSep + 1);
                // single level
                assertTrue("First component of link not found" + link, listLinks.contains(link));
            }
        }
    }


    @Test
    public void testDirEnum () throws CIFSException, MalformedURLException, UnknownHostException {
        try ( SmbFile f = createTestDirectory() ) {
            try ( SmbFile a = new SmbFile(f, "a");
                  SmbFile b = new SmbFile(f, "b");
                  SmbFile c = new SmbFile(f, "c") ) {

                a.createNewFile();
                b.createNewFile();
                c.createNewFile();

                String[] names = f.list();
                assertNotNull(names);
                assertEquals(3, names.length);
                Arrays.sort(names);
                Assert.assertArrayEquals(new String[] {
                    "a", "b", "c"
                }, names);

                SmbFile[] files = f.listFiles();
                assertNotNull(files);
                assertEquals(3, files.length);

                for ( SmbFile cf : files ) {
                    assertTrue(cf.exists());
                    cf.close();
                }
            }
            finally {
                f.delete();
            }
        }
    }


    @Test
    public void testEnumDeepUnresolved () throws IOException {
        try ( SmbFile r = getDefaultShareRoot();
              SmbFile f = new SmbFile(r, "enum-test/a/b/") ) {

            try ( SmbResource c = f.resolve("c/") ) {
                if ( !c.exists() ) {
                    c.mkdirs();
                }
            }

            Set<String> names = new HashSet<>();
            try ( CloseableIterator<SmbResource> chld = f.children() ) {
                while ( chld.hasNext() ) {

                    try ( SmbResource next = chld.next() ) {
                        try ( CloseableIterator<SmbResource> children = next.children() ) {}
                        names.add(next.getName());
                    }
                }
            }

            assertTrue("Test directory  enum-test/a/b/c/ not found", names.contains("c/"));
        }

        try ( SmbFile r = getDefaultShareRoot();
              SmbFile f = new SmbFile(r, "enum-test/a/b/c/") ) {
            f.exists();
        }

    }


    @Test
    public void testEnumDeepUnresolvedCasing () throws IOException {

        String testShareURL = getTestShareURL().toUpperCase(Locale.ROOT);

        try ( SmbFile r = new SmbFile(testShareURL, withTestNTLMCredentials(getContext()));
              SmbFile f = new SmbFile(r, "enum-test/a/b/") ) {

            try ( SmbResource c = f.resolve("c/") ) {
                if ( !c.exists() ) {
                    c.mkdirs();
                }
            }

            Set<String> names = new HashSet<>();
            try ( CloseableIterator<SmbResource> chld = f.children() ) {
                while ( chld.hasNext() ) {

                    try ( SmbResource next = chld.next() ) {
                        try ( CloseableIterator<SmbResource> children = next.children() ) {}
                        names.add(next.getName());
                    }
                }
            }

            assertTrue("Test directory  enum-test/a/b/c/ not found", names.contains("c/"));
        }

        try ( SmbFile r = getDefaultShareRoot();
              SmbFile f = new SmbFile(r, "enum-test/a/b/c/") ) {
            f.exists();
        }

    }


    @Test
    public void testDirFilenameFilterEnum () throws CIFSException, MalformedURLException, UnknownHostException {
        try ( SmbFile f = createTestDirectory() ) {
            try ( SmbFile a = new SmbFile(f, "a.txt");
                  SmbFile b = new SmbFile(f, "b.txt");
                  SmbFile c = new SmbFile(f, "c.bar") ) {

                a.createNewFile();
                b.createNewFile();
                c.createNewFile();

                String[] names = f.list(new SmbFilenameFilter() {

                    @Override
                    public boolean accept ( SmbFile dir, String name ) throws SmbException {
                        return name.endsWith(".txt");
                    }
                });
                assertNotNull(names);
                assertEquals(2, names.length);
                Arrays.sort(names);
                Assert.assertArrayEquals(new String[] {
                    "a.txt", "b.txt"
                }, names);

                SmbFile[] files = f.listFiles(new SmbFilenameFilter() {

                    @Override
                    public boolean accept ( SmbFile dir, String name ) throws SmbException {
                        return name.equals("c.bar");
                    }
                });
                assertNotNull(files);
                assertEquals(1, files.length);

                for ( SmbFile cf : files ) {
                    assertTrue(cf.exists());
                    cf.close();
                }
            }
            finally {
                f.delete();
            }
        }
    }


    @Test
    public void testDirDosFilterEnum () throws CIFSException, MalformedURLException, UnknownHostException {
        try ( SmbFile f = createTestDirectory() ) {
            try ( SmbFile a = new SmbFile(f, "a.txt");
                  SmbFile b = new SmbFile(f, "b.txt");
                  SmbFile c = new SmbFile(f, "c.bar") ) {

                a.createNewFile();
                b.createNewFile();
                c.createNewFile();

                SmbFile[] files = f.listFiles(new DosFileFilter("*.txt", -1));
                assertNotNull(files);
                assertEquals(2, files.length);
                for ( SmbFile cf : files ) {
                    assertTrue(cf.exists());
                    cf.close();
                }
            }
            finally {
                f.delete();
            }
        }
    }


    @Test
    public void testPatternEnum () throws CIFSException, MalformedURLException, UnknownHostException {
        try ( SmbFile f = createTestDirectory() ) {
            try ( SmbFile a = new SmbFile(f, "a.txt");
                  SmbFile b = new SmbFile(f, "b.txt");
                  SmbFile c = new SmbFile(f, "c.bar") ) {

                a.createNewFile();
                b.createNewFile();
                c.createNewFile();

                SmbFile[] files = f.listFiles("*.txt");
                assertNotNull(files);
                assertEquals(2, files.length);
                for ( SmbFile cf : files ) {
                    assertTrue(cf.exists());
                    cf.close();
                }

                int n = 0;
                try ( CloseableIterator<SmbResource> children = f.children("*.txt") ) {
                    while ( children.hasNext() ) {
                        try ( SmbResource r = children.next() ) {
                            assertTrue(r.exists());
                            n++;
                        }
                    }
                }
                assertEquals(2, n);
            }
            finally {
                f.delete();
            }
        }
    }


    @Test
    public void testAttributeEnum () throws CIFSException, MalformedURLException, UnknownHostException {

        try ( SmbFile f = createTestDirectory() ) {
            try ( SmbFile a = new SmbFile(f, "a/");
                  SmbFile b = new SmbFile(f, "b.txt");
                  SmbFile c = new SmbFile(f, "c.bar") ) {

                a.mkdir();

                b.createNewFile();
                boolean haveHidden = false;
                try {
                    b.setAttributes(SmbConstants.ATTR_HIDDEN);
                    haveHidden = true;
                }
                catch ( SmbUnsupportedOperationException e ) {}

                c.createNewFile();
                boolean haveArchive = false;
                try {
                    c.setAttributes(SmbConstants.ATTR_ARCHIVE);
                    haveArchive = true;
                }
                catch ( SmbUnsupportedOperationException e ) {}

                SmbFile[] dirs = f.listFiles(new DosFileFilter("*", SmbConstants.ATTR_DIRECTORY));
                assertNotNull(dirs);
                assertEquals(1, dirs.length);

                if ( haveHidden ) {
                    SmbFile[] hidden = f.listFiles(new DosFileFilter("*", SmbConstants.ATTR_HIDDEN));
                    assertNotNull(hidden);
                    assertEquals(1, hidden.length);
                }

                if ( haveArchive ) {
                    SmbFile[] archive = f.listFiles(new DosFileFilter("*", SmbConstants.ATTR_ARCHIVE));
                    assertNotNull(archive);
                    assertEquals(1, archive.length);
                }
            }
            finally {
                f.delete();
            }
        }
    }


    @Test
    public void testEmptyEnum () throws CIFSException, MalformedURLException, UnknownHostException {
        try ( SmbFile f = createTestDirectory() ) {
            try {
                SmbFile[] files = f.listFiles(new DosFileFilter("*.txt", 0));
                assertNotNull(files);
                assertEquals(0, files.length);

                files = f.listFiles();
                assertNotNull(files);
                assertEquals(0, files.length);
            }
            finally {
                f.delete();
            }
        }
    }


    @Test
    // BUG #15
    // this cannot be reproduced against samba, samba always subtracts
    // 8 bytes from the output buffer length, probably to mitigate
    // against this issue
    public void testEnumBufferSize () throws IOException {
        CIFSContext ctx = getContext();
        int origBufferSize = ctx.getConfig().getMaximumBufferSize();
        // odd buffer size that does match the alignment
        int tryBufferSize = 1023;
        final int bufSize[] = new int[] {
            origBufferSize
        };
        ctx = withConfig(ctx, new DelegatingConfiguration(ctx.getConfig()) {

            @Override
            public int getMaximumBufferSize () {
                return bufSize[ 0 ];
            }
        });
        ctx = withTestNTLMCredentials(ctx);
        try ( SmbResource root = ctx.get(getTestShareURL());
              SmbResource f = root.resolve(makeRandomDirectoryName()) ) {

            try ( SmbTreeHandle treeHandle = ( (SmbFile) root ).getTreeHandle() ) {
                Assume.assumeTrue("Not SMB2", treeHandle.isSMB2());
            }

            f.mkdir();
            try {

                for ( int i = 0; i < 5; i++ ) {
                    // each entry 94 byte + 2 * name length
                    // = 128 byte per entry
                    try ( SmbResource r = f.resolve(String.format("%04x%s", i, repeat('X', 13))) ) {
                        r.createNewFile();
                    }
                }
                // == 5*128 = 640

                // . and .. entries = 200 byte (includes alignment)

                // + 64 byte header
                // + 8 byte query response overhead
                // + 110 bytes entry
                // -> 1022 predicted message size <= 1023 maximum buffer size
                // 112 bytes to alignment
                // -> aligned to 1024 > 1023 maximum buffer size

                // 110 byte entry = 16 byte name = 8 char length
                try ( SmbResource r = f.resolve(repeat('Y', 8)) ) {
                    r.createNewFile();
                }

                bufSize[ 0 ] = tryBufferSize;

                try ( CloseableIterator<SmbResource> chld = f.children() ) {
                    while ( chld.hasNext() ) {
                        chld.next();
                    }
                }
                finally {
                    bufSize[ 0 ] = origBufferSize;
                }
            }
            finally {
                f.delete();
            }
        }
    }


    @Test
    // BUG #16
    public void testListCountRollover () throws IOException {
        testListCount(5, 4); // 4 + 2 (.,..) files
    }


    @Test
    // BUG #16
    public void testListCountExact () throws IOException {
        testListCount(5, 3); // 3 + 2 (.,..) files
    }


    @Test
    // BUG #16
    public void testListCountMoreThanTwo () throws IOException {
        testListCount(5, 10); // 10 + 2 (.,..) files
    }


    private void testListCount ( final int pageSize, int numFiles ) throws CIFSException {
        CIFSContext ctx = getContext();
        ctx = withConfig(ctx, new DelegatingConfiguration(ctx.getConfig()) {

            @Override
            public int getListCount () {
                return pageSize;
            }
        });
        ctx = withTestNTLMCredentials(ctx);
        try ( SmbResource root = ctx.get(getTestShareURL());
              SmbResource f = root.resolve(makeRandomDirectoryName()) ) {
            f.mkdir();
            try {
                for ( int i = 0; i < numFiles; i++ ) {
                    try ( SmbResource r = f.resolve(String.format("%04x", i)) ) {
                        r.createNewFile();
                    }
                }

                int cnt = 0;
                try ( CloseableIterator<SmbResource> chld = f.children() ) {
                    while ( chld.hasNext() ) {
                        try ( SmbResource next = chld.next() ) {
                            cnt++;
                        }
                    }
                }

                assertEquals(numFiles, cnt);
            }
            finally {
                f.delete();
            }
        }
    }


    @Test
    // BUG #61
    public void testListTrailingSlash () throws MalformedURLException, UnknownHostException, CIFSException {
        CIFSContext ctx = getContext();
        try ( SmbFile f = createTestDirectory() ) {
            try ( SmbFile a = new SmbFile(f, "a/");
                  SmbFile b = new SmbFile(a, "b.txt");
                  SmbFile c = new SmbFile(a, "c.txt") ) {

                a.mkdir();
                b.createNewFile();
                c.createNewFile();

                CIFSContext tc = withTestNTLMCredentials(ctx);

                String url = getTestShareURL() + f.getName() + "a/";

                try ( SmbFile f2 = new SmbFile(url, tc) ) {
                    f2.list();
                }
            }
            finally {
                f.delete();
            }
        }

    }


    private static String repeat ( char c, int n ) {
        char chs[] = new char[n];
        for ( int i = 0; i < n; i++ ) {
            chs[ i ] = c;
        }
        return new String(chs);
    }

}
