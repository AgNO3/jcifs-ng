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
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.UnknownHostException;
import java.util.Collection;
import java.util.Map;

import jcifs.CIFSContext;
import jcifs.smb.*;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import jcifs.CIFSException;
import jcifs.SmbResource;
import jcifs.SmbTreeHandle;


/**
 * @author mbechler
 *
 */
@RunWith ( Parameterized.class )
@SuppressWarnings ( "javadoc" )
public class FileOperationsTest extends BaseCIFSTest {

    public FileOperationsTest ( String name, Map<String, String> properties ) {
        super(name, properties);
    }


    @Parameters ( name = "{0}" )
    public static Collection<Object> configs () {
        return getConfigs("smb1", "noUnicode", "forceUnicode", "noNTStatus", "noNTSmbs", "smb2", "smb30", "smb31");
    }


    @Test
    public void testRenameFile () throws CIFSException, MalformedURLException, UnknownHostException {
        try ( SmbFile defaultShareRoot = getDefaultShareRoot();
              SmbResource f = new SmbFile(defaultShareRoot, makeRandomName());
              SmbFile f2 = new SmbFile(defaultShareRoot, makeRandomName()) ) {
            f.createNewFile();
            boolean renamed = false;
            try {
                f.renameTo(f2);
                try {
                    assertTrue(f2.exists());
                    renamed = true;
                }
                finally {
                    f2.delete();
                }
            }
            finally {
                if ( !renamed && f.exists() ) {
                    f.delete();
                }
            }
        }
    }


    @Test
    // BUG #69
    public void testRenameFileAttrCache () throws CIFSException, MalformedURLException, UnknownHostException {
        String nameSrc = makeRandomName();
        String nameTgt = makeRandomName();
        try ( SmbFile defaultShareRoot = getDefaultShareRoot();
              SmbResource f = new SmbFile(defaultShareRoot, nameSrc);
              SmbFile f2 = new SmbFile(defaultShareRoot, nameTgt) ) {
            f.createNewFile();
            boolean renamed = false;
            try {
                f.renameTo(f2);
                try {
                    assertTrue(f2.exists());
                    renamed = true;

                    assertEquals(nameSrc, f.getName());
                    assertEquals(nameTgt, f2.getName());

                    assertFalse(f.exists());
                }
                finally {
                    f2.delete();
                }
            }
            finally {
                if ( !renamed && f.exists() ) {
                    f.delete();
                }
            }
        }
    }


    @Test
    public void testRenameOverwrite () throws CIFSException, MalformedURLException, UnknownHostException {
        try ( SmbFile defaultShareRoot = getDefaultShareRoot();
              SmbResource f = new SmbFile(defaultShareRoot, makeRandomName());
              SmbResource tgt = new SmbFile(defaultShareRoot, makeRandomName()) ) {
            f.createNewFile();
            tgt.createNewFile();
            boolean renamed = false;
            try {
                f.renameTo(tgt, true);
                try {
                    assertTrue(tgt.exists());
                    renamed = true;
                }
                finally {
                    tgt.delete();
                }
            }
            catch ( SmbUnsupportedOperationException e ) {
                try ( SmbTreeHandle th = defaultShareRoot.getTreeHandle() ) {
                    Assume.assumeTrue("Not SMB2", th.isSMB2());
                }
                throw e;
            }
            finally {
                if ( !renamed && f.exists() ) {
                    f.delete();
                }
            }
        }
    }


    @Test
    public void testRenameDifferentTrees () throws CIFSException, MalformedURLException, UnknownHostException {
        try ( SmbFile defaultShareRoot = getDefaultShareRoot();
              SmbResource f = new SmbFile(defaultShareRoot, makeRandomName());
              SmbResource p = new SmbFile(getTestShareGuestURL(), getContext());
              SmbResource tgt = new SmbFile(p, "other-share") ) {
            f.createNewFile();
            boolean renamed = false;
            try {
                f.renameTo(tgt, true);
                Assert.assertFalse("Should not be able to rename between trees", true);
            }
            catch ( SmbUnsupportedOperationException e ) {
                try ( SmbTreeHandle th = defaultShareRoot.getTreeHandle() ) {
                    Assume.assumeTrue("Not SMB2", th.isSMB2());
                }
                throw e;
            }
            catch ( SmbAuthException e )  {
                // guest share not accessible
            }
            catch ( SmbException e) {
                if ("Cannot rename between different trees".equals(e.getMessage())) {
                    // expected
                    return;
                }
                throw e;
            }
            finally {
                if ( !renamed && f.exists() ) {
                    f.delete();
                }
            }
        }
    }


    @Test
    public void testMoveFile () throws CIFSException, MalformedURLException, UnknownHostException {
        try ( SmbFile defaultShareRoot = getDefaultShareRoot();
              SmbFile d = createTestDirectory();
              SmbResource f = new SmbFile(defaultShareRoot, makeRandomName());
              SmbFile f2 = new SmbFile(d, makeRandomName()) ) {
            f.createNewFile();
            boolean renamed = false;
            try {
                f.renameTo(f2);
                try {
                    assertTrue(f2.exists());
                    renamed = true;
                }
                finally {
                    f2.delete();
                }
            }
            finally {
                if ( !renamed && f.exists() ) {
                    f.delete();
                }
                d.delete();
            }
        }
    }


    @Test
    public void testRenameDirectory () throws CIFSException, MalformedURLException, UnknownHostException {
        try ( SmbFile defaultShareRoot = getDefaultShareRoot();
              SmbFile d = createTestDirectory();
              SmbResource d1 = new SmbFile(defaultShareRoot, makeRandomDirectoryName());
              SmbFile d2 = new SmbFile(d, makeRandomDirectoryName()) ) {
            d1.mkdir();
            boolean renamed = false;
            try {
                d1.renameTo(d2);
                try {
                    assertTrue(d2.exists());
                    renamed = true;
                }
                finally {
                    d2.delete();
                }
            }
            finally {
                if ( !renamed && d1.exists() ) {
                    d1.delete();
                }
                d.delete();
            }
        }
    }


    @Test
    public void testMoveDirectory () throws CIFSException, MalformedURLException, UnknownHostException {
        try ( SmbFile defaultShareRoot = getDefaultShareRoot();
              SmbResource d1 = new SmbFile(defaultShareRoot, makeRandomDirectoryName());
              SmbFile d2 = new SmbFile(defaultShareRoot, makeRandomDirectoryName()) ) {
            d1.mkdir();
            boolean renamed = false;
            try {
                d1.renameTo(d2);
                try {
                    assertTrue(d2.exists());
                    renamed = true;
                }
                finally {
                    d2.delete();
                }
            }
            finally {
                if ( !renamed && d1.exists() ) {
                    d1.delete();
                }
            }
        }
    }


    @Test
    public void testCopyEmpty () throws IOException {
        try ( SmbFile f = createTestFile() ) {
            try ( SmbFile d1 = createTestDirectory();
                  SmbFile t = new SmbFile(d1, makeRandomName()) ) {
                try {
                    f.copyTo(t);
                    assertTrue(f.exists());
                    assertEquals(f.length(), t.length());
                    assertEquals(f.getAttributes(), t.getAttributes());
                }
                finally {
                    d1.delete();
                }
            }
            finally {
                f.delete();
            }
        }
    }


    @Test
    public void testCopyFile () throws IOException {
        int bufSize = 65536;
        long length = 4096 * 16;
        try ( SmbFile f = createTestFile() ) {
            try ( SmbFile d1 = createTestDirectory();
                  SmbFile t = new SmbFile(d1, makeRandomName()) ) {
                try {
                    try ( OutputStream os = f.getOutputStream() ) {
                        ReadWriteTest.writeRandom(bufSize, length, os);
                    }

                    f.copyTo(t);
                    assertTrue(f.exists());
                    assertEquals(f.length(), t.length());
                    assertEquals(f.getAttributes(), t.getAttributes());

                    try ( InputStream is = t.getInputStream() ) {
                        ReadWriteTest.verifyRandom(bufSize, length, is);
                    }
                }
                finally {
                    d1.delete();
                }
            }
            finally {
                f.delete();
            }
        }
    }


    // #173
    @Test
    public void testCopyTargetExists () throws IOException {
        int bufSize = 65536;
        long length = 4096 * 16;
        try ( SmbFile f = createTestFile() ) {
            try ( SmbFile d1 = createTestDirectory();
                  SmbFile t = new SmbFile(d1, makeRandomName()) ) {
                try {
                    try ( OutputStream os = f.getOutputStream() ) {
                        ReadWriteTest.writeRandom(bufSize, length, os);
                    }

                    try ( OutputStream os = t.getOutputStream() ) {
                        ReadWriteTest.writeRandom(bufSize, 2 * length, os);
                    }

                    f.copyTo(t);
                    assertTrue(f.exists());
                    assertEquals(f.length(), t.length());
                    assertEquals(f.getAttributes(), t.getAttributes());

                    try ( InputStream is = t.getInputStream() ) {
                        ReadWriteTest.verifyRandom(bufSize, length, is);
                    }
                }
                finally {
                    d1.delete();
                }
            }
            finally {
                f.delete();
            }
        }
    }


    @Test
    public void testCopyFileLarge () throws IOException {
        long length = 4096 * 16 * 1024;
        try ( SmbFile f = createTestFile();
              SmbTreeHandle treeHandle = f.getTreeHandle() ) {
            // this is tremendously slow on SMB1
            try {
                Assume.assumeTrue("Not SMB2", treeHandle.isSMB2());

                try ( SmbFile d1 = createTestDirectory();
                      SmbFile t = new SmbFile(d1, makeRandomName()) ) {
                    try {
                        try ( SmbRandomAccessFile ra = f.openRandomAccess("rw") ) {
                            ra.setLength(length);
                        }

                        f.copyTo(t);
                        assertTrue(f.exists());
                        assertEquals(f.length(), t.length());
                        assertEquals(f.getAttributes(), t.getAttributes());
                    }
                    finally {
                        d1.delete();
                    }
                }
            }
            finally {
                f.delete();
            }
        }
    }


    @Test
    public void testCopyFileLargeNoAlign () throws IOException {
        long length = 4096 * 16 * 1024 + 13;
        try ( SmbFile f = createTestFile();
              SmbTreeHandle treeHandle = f.getTreeHandle() ) {
            // this is tremendously slow on SMB1
            try {
                Assume.assumeTrue("Not SMB2", treeHandle.isSMB2());
                try ( SmbFile d1 = createTestDirectory();
                      SmbFile t = new SmbFile(d1, makeRandomName()) ) {
                    try {
                        try ( SmbRandomAccessFile ra = f.openRandomAccess("rw") ) {
                            ra.setLength(length);
                        }

                        f.copyTo(t);
                        assertTrue(f.exists());
                        assertEquals(f.length(), t.length());
                        assertEquals(f.getAttributes(), t.getAttributes());
                    }
                    finally {
                        d1.delete();
                    }
                }
            }
            finally {
                f.delete();
            }
        }
    }


    @Test
    public void testCopyFileUnresolved () throws IOException {
        int bufSize = 65536;
        long length = 4096 * 16 + 512;
        try ( SmbFile d = createTestDirectory();
              SmbFile f = new SmbFile(d, makeRandomName()) ) {
            f.createNewFile();

            try ( SmbFile t = new SmbFile(getDefaultShareRoot(), makeRandomName()) ) {
                try {
                    try ( OutputStream os = f.getOutputStream() ) {
                        ReadWriteTest.writeRandom(bufSize, length, os);
                    }
                    f.copyTo(t);
                    assertTrue(f.exists());
                    assertEquals(f.length(), t.length());
                    assertEquals(f.getAttributes(), t.getAttributes());

                    try ( InputStream is = t.getInputStream() ) {
                        ReadWriteTest.verifyRandom(bufSize, length, is);
                    }
                }
                finally {
                    t.delete();
                }
            }
            finally {
                d.delete();
            }
        }
    }


    @Test
    public void testCopyDir () throws IOException {
        int bufSize = 65536;
        long length = 4096 * 16 + 512;
        try ( SmbFile f = createTestDirectory();
              SmbResource e = new SmbFile(f, "test") ) {
            e.createNewFile();

            try ( OutputStream os = e.openOutputStream() ) {
                ReadWriteTest.writeRandom(bufSize, length, os);
            }

            try ( SmbFile d1 = createTestDirectory();
                  SmbFile t = new SmbFile(d1, makeRandomName()) ) {
                try {
                    f.copyTo(t);
                    assertTrue(f.exists());

                    try ( SmbResource e2 = new SmbFile(t, "test") ) {
                        assertTrue(e2.exists());
                        try ( InputStream is = e2.openInputStream() ) {
                            ReadWriteTest.verifyRandom(bufSize, length, is);
                        }
                    }
                }
                finally {
                    d1.delete();
                }
            }
            finally {
                f.delete();
            }
        }
    }


    @Test
    public void testMkDirs () throws CIFSException, MalformedURLException, UnknownHostException {
        try ( SmbFile r = createTestDirectory();
              SmbResource e = new SmbFile(r, "foo/bar/test/") ) {
            try {
                e.mkdirs();
            }
            finally {
                r.delete();
            }
        }
    }

    @Test
    public void testCopyMultipath() throws IOException {
        int bufSize = 65536;
        long length = 1024;
        String uncA = getRequiredProperty("test.dfs.multipath.a");
        String uncB = getRequiredProperty("test.dfs.multipath.b");

        CIFSContext ctx = withTestNTLMCredentials(getContext());
        try {
            try (SmbResource a = ctx.get(uncA); SmbResource as = a.resolve("test-src")) {
                try (OutputStream os = as.openOutputStream()) {
                    ReadWriteTest.writeRandom(bufSize, length, os);
                }
            }


            try (SmbResource a = ctx.get(uncA);
                 SmbResource b = ctx.get(uncB);
                 SmbResource src = a.resolve("test-src");
                 SmbResource tgt = b.resolve("test-tgt")) {
                src.copyTo(tgt);
            }
        } finally {
            try {
                ctx.get(uncA).resolve("test-src").delete();
            } catch (CIFSException ignored) {}
            try {
                ctx.get(uncB).resolve("test-tgt").delete();
            } catch (CIFSException ignored) {}
        }
    }
}
