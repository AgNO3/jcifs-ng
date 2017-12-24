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


import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.UnknownHostException;
import java.util.Collection;
import java.util.Map;
import java.util.Random;

import org.bouncycastle.util.Arrays;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSException;
import jcifs.SmbPipeHandle;
import jcifs.SmbPipeResource;
import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;
import jcifs.smb.SmbNamedPipe;
import jcifs.smb.SmbRandomAccessFile;


/**
 * @author mbechler
 *
 */
@RunWith ( Parameterized.class )
@SuppressWarnings ( "javadoc" )
public class ReadWriteTest extends BaseCIFSTest {

    private static final Logger log = LoggerFactory.getLogger(ReadWriteTest.class);


    public ReadWriteTest ( String name, Map<String, String> properties ) {
        super(name, properties);
    }

    private static final long SEED = ( new Random() ).nextLong();


    @Override
    @Before
    public void setUp () throws Exception {
        super.setUp();
    }


    static Random getRandom () {
        return new Random(SEED);
    }


    @Parameters ( name = "{0}" )
    public static Collection<Object> configs () {
        return getConfigs("smb1", "noLargeReadWrite", "noNTSmbs", "forceSigning", "smb2", "smb30", "smb31");
    }


    @Test
    public void test () throws IOException {
        runReadWriteTest(4096, 4 * 4096);
    }


    @Test
    public void testExactWrite () throws IOException {
        runReadWriteTest(4096, 4096);
    }


    @Test
    public void testSmallWrite () throws IOException {
        runReadWriteTest(4096, 1013);
    }


    @Test
    public void testLargeBuf () throws IOException {
        runReadWriteTest(65465, 65466);
    }


    @Test
    public void testLargeBufExact () throws IOException {
        runReadWriteTest(65465, 65465);
    }


    @Test
    public void testTrucation () throws IOException {
        try ( SmbFile f = createTestFile() ) {
            try {
                try ( OutputStream os = f.openOutputStream() ) {
                    writeRandom(4096, 3072, os);
                }

                // this should truncate
                try ( OutputStream os = f.openOutputStream() ) {
                    writeRandom(4096, 1024, os);
                }

                try ( InputStream is = f.getInputStream() ) {
                    verifyRandom(4096, 1024, true, is);
                }
            }
            finally {
                f.delete();
            }
        }
    }


    @Test
    public void testAppend () throws IOException {
        try ( SmbFile f = createTestFile() ) {
            try {
                try ( OutputStream os = f.openOutputStream() ) {
                    writeRandom(4096, 3072, os);
                }

                // this should NOT truncate
                try ( OutputStream os = f.openOutputStream(true) ) {
                    writeRandom(4096, 1024, os);
                }

                try ( InputStream is = f.getInputStream() ) {
                    verifyRandom(4096, 3072, false, is);
                    verifyRandom(4096, 1024, true, is);
                }
            }
            finally {
                f.delete();
            }
        }
    }


    private void runReadWriteTest ( int bufSize, long length ) throws MalformedURLException, UnknownHostException, SmbException, IOException {
        try ( SmbFile f = createTestFile() ) {
            try {
                try ( OutputStream os = f.getOutputStream() ) {
                    writeRandom(bufSize, length, os);
                }

                assertEquals("File size matches", length, f.length());

                try ( InputStream is = f.getInputStream() ) {
                    verifyRandom(bufSize, length, is);
                }

            }
            finally {
                f.delete();
            }
        }
    }


    @Test
    public void testRandomAccess () throws CIFSException, MalformedURLException, UnknownHostException {
        try ( SmbFile f = createTestFile() ) {
            try {
                try ( SmbRandomAccessFile raf = new SmbRandomAccessFile(f, "rw") ) {

                }
            }
            finally {
                f.delete();
            }
        }
    }


    private String getFifoPipeUrl () {
        String testFifoPipe = getProperties().get(TestProperties.TEST_FIFO_PIPE);
        Assume.assumeNotNull(testFifoPipe);
        return "smb://" + getTestServer() + "/IPC$/" + testFifoPipe;
    }


    private String getTransactPipeUrl () {
        String testTransactPipe = getProperties().get(TestProperties.TEST_TRANSACT_PIPE);
        Assume.assumeNotNull(testTransactPipe);
        return "smb://" + getTestServer() + "/IPC$/" + testTransactPipe;
    }


    private String getCallPipeUrl () {
        String testCallPipe = getProperties().get(TestProperties.TEST_CALL_PIPE);
        Assume.assumeNotNull(testCallPipe);
        return "smb://" + getTestServer() + "/IPC$/" + testCallPipe;
    }


    @Test
    public void testTransactPipe () throws IOException {
        try ( SmbNamedPipe f = new SmbNamedPipe(
            getTransactPipeUrl(),
            SmbPipeResource.PIPE_TYPE_RDWR | SmbPipeResource.PIPE_TYPE_TRANSACT,
            withTestNTLMCredentials(getContext())) ) {
            try ( SmbPipeHandle p = f.openPipe() ) {
                try ( OutputStream os = p.getOutput() ) {
                    writeRandom(1024, 1024, os);
                    try ( InputStream is = p.getInput() ) {
                        verifyRandom(1024, 1024, is);
                    }
                }
            }
            catch ( SmbException e ) {
                if ( e.getNtStatus() == 0xC00000BB ) {
                    Assume.assumeTrue("Server does not support pipes or it does not exist", false);
                }
                throw e;
            }
        }
    }


    @Test
    public void testCallPipe () throws IOException {
        try ( SmbNamedPipe f = new SmbNamedPipe(
            getCallPipeUrl(),
            SmbPipeResource.PIPE_TYPE_RDWR | SmbPipeResource.PIPE_TYPE_CALL,
            withTestNTLMCredentials(getContext())) ) {
            try ( SmbPipeHandle p = f.openPipe() ) {
                try ( OutputStream os = p.getOutput() ) {
                    writeRandom(1024, 1024, os);
                    try ( InputStream is = p.getInput() ) {
                        verifyRandom(1024, 1024, is);
                    }
                }
            }
            catch ( SmbException e ) {
                if ( e.getNtStatus() == 0xC00000BB ) {
                    Assume.assumeTrue("Server does not support pipes or it does not exist", false);
                }
                throw e;
            }
        }
    }


    @Test
    public void testFifoPipe () throws IOException {
        try ( SmbNamedPipe f = new SmbNamedPipe(getFifoPipeUrl(), SmbPipeResource.PIPE_TYPE_RDWR, withTestNTLMCredentials(getContext())) ) {
            try ( SmbPipeHandle p = f.openPipe() ) {
                try ( OutputStream os = p.getOutput() ) {
                    writeRandom(1024, 1024, os);
                    try ( InputStream is = p.getInput() ) {
                        verifyRandom(1024, 1024, is);
                    }
                }
            }
            catch ( SmbException e ) {
                if ( e.getNtStatus() == 0xC0000034 ) {
                    Assume.assumeTrue("Server does not support pipes or it does not exist", false);
                }
                throw e;
            }
        }
    }


    @Test
    public void testFifoPipeTwoHandles () throws IOException {
        try ( SmbNamedPipe s = new SmbNamedPipe(getFifoPipeUrl(), SmbPipeResource.PIPE_TYPE_WRONLY, withTestNTLMCredentials(getContext()));
              SmbNamedPipe t = new SmbNamedPipe(getFifoPipeUrl(), SmbPipeResource.PIPE_TYPE_RDONLY, withTestNTLMCredentials(getContext())) ) {
            try ( SmbPipeHandle sp = s.openPipe();
                  SmbPipeHandle tp = t.openPipe() ) {
                try ( OutputStream os = sp.getOutput() ) {
                    writeRandom(1024, 1024, os);
                }
                try ( InputStream is = tp.getInput() ) {
                    verifyRandom(1024, 1024, is);
                }
            }
            catch ( SmbException e ) {
                if ( e.getNtStatus() == 0xC0000034 ) {
                    Assume.assumeTrue("Server does not support pipes or it does not exist", false);
                }
                throw e;
            }
        }
    }


    @Test
    public void testReadWriteOneHandle () throws IOException {
        try ( SmbFile f = createTestFile() ) {
            try ( SmbFile s = new SmbFile(f.getURL().toString(), withTestNTLMCredentials(getContext())) ) {
                try ( OutputStream os = s.getOutputStream();
                      InputStream is = s.getInputStream() ) {
                    writeRandom(1024, 1024, os);
                    verifyRandom(1024, 1024, is);
                }
            }
            finally {
                f.delete();
            }
        }
    }


    @Test
    public void testReadWriteTwoHandles () throws IOException {
        try ( SmbFile f = createTestFile() ) {
            try ( SmbFile s = new SmbFile(f.getURL().toString(), withTestNTLMCredentials(getContext()));
                  SmbFile t = new SmbFile(f.getURL().toString(), withTestNTLMCredentials(getContext())) ) {
                try ( OutputStream os = s.getOutputStream();
                      InputStream is = t.getInputStream() ) {
                    writeRandom(1024, 1024, os);
                    verifyRandom(1024, 1024, is);
                }
            }
            finally {
                f.delete();
            }
        }
    }


    @Test
    public void testLargeBufSmallWrite () throws IOException {
        try ( SmbFile f = createTestFile() ) {
            try {
                int bufSize = 65535;
                long length = 1024;
                try ( OutputStream os = f.getOutputStream() ) {
                    writeRandom(bufSize, length, os);
                }

                try ( InputStream is = f.getInputStream() ) {
                    verifyRandom(bufSize, length, is);
                }

            }
            finally {
                f.delete();
            }
        }
    }


    static void verifyRandom ( int bufSize, long length, InputStream is ) throws IOException {
        verifyRandom(bufSize, length, true, is);
    }


    static void verifyRandom ( int bufSize, long length, boolean expectEof, InputStream is ) throws IOException {
        long start = System.currentTimeMillis();
        byte buffer[] = new byte[bufSize];
        long p = 0;
        Random r = getRandom();
        while ( p < length ) {

            int rs = Math.min(bufSize, (int) ( length - p ));
            int read = is.read(buffer, 0, rs);
            if ( read < 0 ) {
                fail("Unexpected EOF at " + p);
            }

            byte verify[] = new byte[read];
            randBytes(r, verify);
            byte actual[] = Arrays.copyOfRange(buffer, 0, read);

            assertArrayEquals("Data matches at offset " + p, actual, verify);

            p += read;
        }
        if ( expectEof ) {
            assertEquals("Expecting EOF", -1, is.read(buffer, 0, 1));
        }
        log.debug("Read " + length + " took " + ( System.currentTimeMillis() - start ));
    }


    /**
     * @param bufSize
     * @param length
     * @param os
     * @throws IOException
     */
    static void writeRandom ( int bufSize, long length, OutputStream os ) throws IOException {
        long start = System.currentTimeMillis();
        byte buffer[] = new byte[bufSize];
        long p = 0;
        Random r = getRandom();
        while ( p < length ) {
            randBytes(r, buffer);
            int w = Math.min(bufSize, (int) ( length - p ));
            os.write(buffer, 0, w);
            p += w;
        }
        log.debug("Write " + length + " took " + ( System.currentTimeMillis() - start ));
    }


    static final void randBytes ( Random r, byte[] buffer ) {
        // regular nextBytes is not reproducible if the reads are not aligned
        for ( int i = 0; i < buffer.length; i++ ) {
            buffer[ i ] = (byte) r.nextInt(256);
        }

    }
}
