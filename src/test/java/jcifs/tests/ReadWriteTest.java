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

import org.apache.log4j.Logger;
import org.bouncycastle.util.Arrays;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

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

    private static final Logger log = Logger.getLogger(ReadWriteTest.class);


    public ReadWriteTest ( String name, Map<String, String> properties ) {
        super(name, properties);
    }

    private long seed;


    @Override
    @Before
    public void setUp () throws Exception {
        this.seed = ( new Random() ).nextLong();
        super.setUp();
    }


    private Random getRandom () {
        Logger.getLogger(ReadWriteTest.class).debug("Seed is " + this.seed);
        return new Random(this.seed);
    }


    @Parameters ( name = "{0}" )
    public static Collection<Object> configs () {
        return getConfigs("noLargeReadWrite", "noNTSmbs", "forceSigning");
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


    private void runReadWriteTest ( int bufSize, long length ) throws MalformedURLException, UnknownHostException, SmbException, IOException {
        SmbFile f = createTestFile();
        try {
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


    @Test
    public void testRandomAccess () throws SmbException, MalformedURLException, UnknownHostException {
        SmbFile f = createTestFile();
        try {
            try ( SmbRandomAccessFile raf = new SmbRandomAccessFile(f, "rw") ) {

            }
        }
        finally {
            f.delete();
        }
    }


    @Test
    public void testPipeOneHandle () throws IOException {
        SmbFile pn = new SmbFile(getDefaultShareRoot(), makeRandomName());
        SmbNamedPipe f = new SmbNamedPipe(pn.getURL().toString(), SmbNamedPipe.PIPE_TYPE_RDWR, withTestNTLMCredentials(getContext()));
        try {
            f.createNewFile();
            try {
                try ( OutputStream os = f.getNamedPipeOutputStream() ) {
                    writeRandom(1024, 1024, os);
                    try ( InputStream is = f.getNamedPipeInputStream() ) {
                        verifyRandom(1024, 1024, is);
                    }
                }
            }
            finally {
                f.delete();
            }
        }
        finally {
            f.close();
        }
    }


    @Test
    public void testPipeTwoHandles () throws IOException {
        SmbFile pn = new SmbFile(getDefaultShareRoot(), makeRandomName());
        SmbNamedPipe s = new SmbNamedPipe(pn.getURL().toString(), SmbNamedPipe.PIPE_TYPE_RDWR, withTestNTLMCredentials(getContext()));
        SmbNamedPipe t = new SmbNamedPipe(pn.getURL().toString(), SmbNamedPipe.PIPE_TYPE_RDONLY, withTestNTLMCredentials(getContext()));
        try {
            s.createNewFile();
            try {
                try ( OutputStream os = s.getNamedPipeOutputStream() ) {
                    writeRandom(1024, 1024, os);
                }
                try ( InputStream is = t.getNamedPipeInputStream() ) {
                    verifyRandom(1024, 1024, is);
                }
            }
            finally {
                s.delete();
            }
        }
        finally {
            s.close();
            t.close();
        }
    }


    @Test
    public void testLargeBufSmallWrite () throws IOException {
        SmbFile f = createTestFile();
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


    /**
     * @param bufSize
     * @param length
     * @param is
     * @throws IOException
     */
    private void verifyRandom ( int bufSize, long length, InputStream is ) throws IOException {
        long start = System.currentTimeMillis();
        byte buffer[] = new byte[bufSize];
        long p = 0;
        Random r = getRandom();
        while ( p < length ) {

            int rs = Math.min(bufSize, (int) ( length - p ));
            int read = is.read(buffer, 0, rs);
            if ( read < 0 ) {
                fail("Unexpected EOF");
            }

            byte verify[] = new byte[read];
            randBytes(r, verify);
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
    private void writeRandom ( int bufSize, long length, OutputStream os ) throws IOException {
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


    private static void randBytes ( Random r, byte[] buffer ) {
        // regular nextBytes is not reproducible if the reads are not aligned
        for ( int i = 0; i < buffer.length; i++ ) {
            buffer[ i ] = (byte) r.nextInt(256);
        }

    }
}
