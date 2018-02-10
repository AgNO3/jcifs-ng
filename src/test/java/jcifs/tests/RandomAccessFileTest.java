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


import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.DataOutput;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.Random;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSException;
import jcifs.SmbRandomAccess;
import jcifs.smb.SmbEndOfFileException;
import jcifs.smb.SmbFile;
import jcifs.smb.SmbFileOutputStream;
import jcifs.smb.SmbRandomAccessFile;


/**
 * @author mbechler
 *
 */
@RunWith ( Parameterized.class )
@SuppressWarnings ( "javadoc" )
public class RandomAccessFileTest extends BaseCIFSTest {

    private static final Logger log = LoggerFactory.getLogger(RandomAccessFileTest.class);


    /**
     * @param name
     * @param properties
     */
    public RandomAccessFileTest ( String name, Map<String, String> properties ) {
        super(name, properties);
    }


    @Parameters ( name = "{0}" )
    public static Collection<Object> configs () {
        return getConfigs("smb1", "noUnicode", "forceUnicode", "noNTStatus", "noNTSmbs", "smb2", "smb30", "smb31");
    }


    @Test
    public void testReadOnly () throws IOException {
        try ( SmbFile f = createTestFile() ) {
            try {
                try ( SmbFileOutputStream os = f.openOutputStream() ) {
                    os.write(new byte[] {
                        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7
                    });
                }

                byte[] buf = new byte[4];
                try ( SmbRandomAccessFile raf = new SmbRandomAccessFile(f, "r") ) {
                    raf.seek(4);
                    raf.readFully(buf);
                }

                Assert.assertArrayEquals(new byte[] {
                    0x4, 0x5, 0x6, 0x7
                }, buf);
            }
            finally {
                f.delete();
            }
        }
    }


    @Test
    public void testReadOnlySeekOOB () throws IOException {
        try ( SmbFile f = createTestFile() ) {
            try {
                try ( SmbFileOutputStream os = f.openOutputStream() ) {
                    os.write(new byte[] {
                        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7
                    });
                }

                try ( SmbRandomAccessFile raf = new SmbRandomAccessFile(f, "r") ) {
                    raf.seek(10);
                    Assert.assertEquals(-1, raf.read());
                }

                byte[] buf = new byte[4];
                try ( SmbRandomAccessFile raf = new SmbRandomAccessFile(f, "r") ) {
                    raf.seek(6);
                    Assert.assertEquals(2, raf.read(buf));
                    Assert.assertArrayEquals(new byte[] {
                        0x6, 0x7, 0x0, 0x0
                    }, buf);
                }

                try ( SmbRandomAccessFile raf = new SmbRandomAccessFile(f, "r") ) {
                    raf.seek(6);
                    try {
                        raf.readFully(buf);
                        Assert.fail("Should have thrown exception");
                    }
                    catch ( SmbEndOfFileException e ) {}
                }

            }
            finally {
                f.delete();
            }
        }
    }


    @Test
    public void testSetLength () throws CIFSException, MalformedURLException, UnknownHostException {
        try ( SmbFile f = createTestFile() ) {
            try {
                long newLength = 4096L;
                try ( SmbRandomAccessFile raf = new SmbRandomAccessFile(f, "rw") ) {
                    raf.setLength(newLength);
                }
                assertEquals(newLength, f.length());
            }
            finally {
                f.delete();
            }
        }
    }


    @Test
    public void testSetLengthTruncate () throws CIFSException, MalformedURLException, UnknownHostException {
        try ( SmbFile f = createTestFile() ) {
            try {
                long newLength = 1024L;
                try ( SmbRandomAccessFile raf = new SmbRandomAccessFile(f, "rw") ) {
                    raf.seek(4096);
                    raf.write(0);
                    raf.setLength(newLength);
                }
                assertEquals(newLength, f.length());
            }
            finally {
                f.delete();
            }
        }
    }


    @Test
    public void testReadWrite () throws IOException {
        try ( SmbFile f = createTestFile() ) {
            try {
                int bufSize = 4096;
                long l = 1024;
                try ( SmbRandomAccessFile raf = new SmbRandomAccessFile(f, "rw") ) {
                    writeRandom(bufSize, l, raf);
                    assertEquals(l, raf.getFilePointer());
                    raf.seek(0);
                    assertEquals(0, raf.getFilePointer());
                    verifyRandom(bufSize, l, raf);
                    assertEquals(l, raf.getFilePointer());
                }
                assertEquals(l, f.length());
            }
            finally {
                f.delete();
            }
        }
    }


    @Test
    public void testReadWriteSeeked () throws IOException {
        try ( SmbFile f = createTestFile() ) {
            try {
                int bufSize = 4096;
                long l = 1024;
                int off = 2048;
                try ( SmbRandomAccessFile raf = new SmbRandomAccessFile(f, "rw") ) {
                    raf.seek(off);
                    writeRandom(bufSize, l, raf);
                    assertEquals(l + off, raf.getFilePointer());
                    raf.seek(off);
                    assertEquals(off, raf.getFilePointer());
                    verifyRandom(bufSize, l, raf);
                    assertEquals(l + off, raf.getFilePointer());
                }
                assertEquals(l + off, f.length());
            }
            finally {
                f.delete();
            }
        }
    }


    @Test
    public void testWriteVerify () throws IOException {
        try ( SmbFile f = createTestFile() ) {
            try {
                int bufSize = 4096;
                int l = 1024;
                int off = 2048;
                try ( SmbRandomAccessFile raf = new SmbRandomAccessFile(f, "rw") ) {
                    raf.seek(off);
                    writeRandom(bufSize, l, raf);
                    assertEquals(l + off, raf.getFilePointer());
                    raf.setLength(raf.getFilePointer() + l);
                }

                try ( InputStream is = f.getInputStream() ) {
                    verifyZero(off, is);
                    ReadWriteTest.verifyRandom(bufSize, l, false, is);
                    verifyZero(l, is);
                }
            }
            finally {
                f.delete();
            }
        }
    }


    @Test
    public void testLargeReadWrite () throws IOException {
        try ( SmbFile f = createTestFile() ) {
            try {
                int bufSize = 64 * 1024 + 512;
                int l = bufSize;
                try ( SmbRandomAccess raf = f.openRandomAccess("rw") ) {
                    writeRandom(bufSize, l, raf);
                }

                try ( SmbRandomAccess raf = f.openRandomAccess("rw") ) {
                    verifyRandom(bufSize, l, raf);
                }
            }
            finally {
                f.delete();
            }
        }
    }


    @Test
    public void testReadFullyMultipleWrites () throws IOException {
        try ( SmbFile f = createTestFile() ) {

            try ( SmbRandomAccess raf = f.openRandomAccess("rw") ) {

                raf.write(new byte[] {
                    0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8
                });
                raf.seek(0);
                assertEquals(0, raf.getFilePointer());

                byte[] buf = new byte[4];

                raf.readFully(buf);
                assertArrayEquals(new byte[] {
                    0x1, 0x2, 0x3, 0x4
                }, buf);
                assertEquals(4, raf.getFilePointer());

                raf.readFully(buf);
                assertArrayEquals(new byte[] {
                    0x5, 0x6, 0x7, 0x8
                }, buf);
                assertEquals(8, raf.getFilePointer());
            }
        }
    }


    private static void verifyZero ( int cnt, InputStream is ) throws IOException {
        byte[] offBuf = new byte[cnt];
        int pos = 0;
        while ( pos < cnt ) {
            int r = is.read(offBuf, pos, offBuf.length - pos);
            if ( r < 0 ) {
                fail("EOF while reading");
            }
            pos += r;
        }

        for ( int i = 0; i < offBuf.length; i++ ) {
            if ( offBuf[ i ] != 0 ) {
                fail("Not zero @ " + i);
            }
        }
    }


    /**
     * @param bufSize
     * @param length
     * @param is
     * @throws IOException
     */
    static void verifyRandom ( int bufSize, long length, SmbRandomAccess is ) throws IOException {
        long start = System.currentTimeMillis();
        byte buffer[] = new byte[bufSize];
        long p = 0;
        Random r = ReadWriteTest.getRandom();
        while ( p < length ) {

            int rs = Math.min(bufSize, (int) ( length - p ));
            int read = is.read(buffer, 0, rs);
            if ( read < 0 ) {
                fail("Unexpected EOF");
            }

            byte verify[] = new byte[read];
            ReadWriteTest.randBytes(r, verify);
            byte actual[] = Arrays.copyOfRange(buffer, 0, read);

            assertArrayEquals("Data matches at offset " + p, actual, verify);

            p += read;
        }
        assertEquals("Expecting EOF", -1, is.read(buffer, 0, 1));
        log.debug("Read " + length + " took " + ( System.currentTimeMillis() - start ));
    }


    /**
     * @param bufSize
     * @param length
     * @param os
     * @throws IOException
     */
    static void writeRandom ( int bufSize, long length, DataOutput os ) throws IOException {
        long start = System.currentTimeMillis();
        byte buffer[] = new byte[bufSize];
        long p = 0;
        Random r = ReadWriteTest.getRandom();
        while ( p < length ) {
            ReadWriteTest.randBytes(r, buffer);
            int w = Math.min(bufSize, (int) ( length - p ));
            os.write(buffer, 0, w);
            p += w;
        }
        log.debug("Write " + length + " took " + ( System.currentTimeMillis() - start ));
    }
}
