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

import java.net.MalformedURLException;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSException;
import jcifs.smb.DosFileFilter;
import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;
import jcifs.smb.SmbFilenameFilter;


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
        return getConfigs("noUnicode", "forceUnicode", "noNTStatus", "noNTSmbs");
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
        try ( SmbFile smbFile = new SmbFile(getDFSRootURL(), withTestNTLMCredentials(getContext())) ) {
            String[] list = smbFile.list();
            assertNotNull(list);
            assertTrue("No share found", list.length > 0);
            log.debug(Arrays.toString(list));
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


    public void testDirDosFilterEnum () throws CIFSException, MalformedURLException, UnknownHostException {
        try ( SmbFile f = createTestDirectory() ) {
            try ( SmbFile a = new SmbFile(f, "a.txt");
                  SmbFile b = new SmbFile(f, "b.txt");
                  SmbFile c = new SmbFile(f, "c.bar") ) {

                a.createNewFile();
                b.createNewFile();
                c.createNewFile();

                SmbFile[] files = f.listFiles(new DosFileFilter("*.txt", 0));
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

}
