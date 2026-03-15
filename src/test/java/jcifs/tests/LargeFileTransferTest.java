/*
 * © 2025 Courville Software
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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jcifs.smb.SmbFile;

/**
 * Test for large file transfers to verify multi-credit support and performance.
 * Compares 64KB (Single-credit) vs 1MB (Multi-credit) transfers.
 */
@RunWith(Parameterized.class)
public class LargeFileTransferTest extends BaseCIFSTest {

    private static final Logger log = LoggerFactory.getLogger(LargeFileTransferTest.class);
    private static final int FILE_SIZE = 64 * 1024 * 1024; // 64 MB
    private static final long DATA_SEED = 0x4A434946534C4E47L;
    private static final int[] BUFFER_SIZES = {
        65536, 1048576
    };
    private final int transportBufferSize;

    private static MessageDigest newDigest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        }
        catch ( NoSuchAlgorithmException e ) {
            throw new IllegalStateException("Missing SHA-256 support", e);
        }
    }

    public LargeFileTransferTest(String name, Map<String, String> properties, int transportBufferSize) {
        super(name, properties);
        this.transportBufferSize = transportBufferSize;
    }

    @Parameters(name = "{0} - {2} bytes buffer")
    public static Collection<Object> configs() {
        List<Object> configs = new ArrayList<>();
        for ( Object baseObj : getConfigs("smb2", "smb30", "smb31") ) {
            Object[] base = (Object[]) baseObj;
            for ( int bufSize : BUFFER_SIZES ) {
                configs.add(new Object[] { base[0] + "-" + bufSize, base[1], bufSize });
            }
        }
        return configs;
    }

    @Override
    @org.junit.Before
    public void setUp() throws Exception {
        // Run through the shared test configuration machinery, varying only transport buffer sizing here.
        getProperties().put("jcifs.smb.client.snd_buf_size", String.valueOf(transportBufferSize));
        getProperties().put("jcifs.smb.client.rcv_buf_size", String.valueOf(transportBufferSize));

        super.setUp();
    }

    @Test
    public void testLargeTransfer() throws IOException {
        String mode = (transportBufferSize > 65536) ? "MULTI-CREDIT (1MB)" : "SINGLE-CREDIT (64KB)";
        
        try (SmbFile f = createTestFile()) {
            log.info(">>> Mode: {} | Size: {} bytes | Target: {}", mode, FILE_SIZE, f.getURL());
            
            // Use a large application buffer to ensure we saturate the transport
            byte[] data = new byte[1024 * 1024]; 
            Random writeRandom = new Random(DATA_SEED);
            MessageDigest expectedDigest = newDigest();
            
            long startWrite = System.currentTimeMillis();
            try (OutputStream os = f.getOutputStream()) {
                int written = 0;
                while (written < FILE_SIZE) {
                    int toWrite = Math.min(data.length, FILE_SIZE - written);
                    writeRandom.nextBytes(data);
                    os.write(data, 0, toWrite);
                    expectedDigest.update(data, 0, toWrite);
                    written += toWrite;
                }
            }
            long endWrite = System.currentTimeMillis();
            double writeTimeSec = (endWrite - startWrite) / 1000.0;
            double writeSpeed = (FILE_SIZE / 1024.0 / 1024.0) / writeTimeSec;

            long startRead = System.currentTimeMillis();
            try (InputStream is = f.getInputStream()) {
                byte[] readBuf = new byte[1024 * 1024];
                MessageDigest actualDigest = newDigest();
                long totalRead = 0;
                int r;
                while ((r = is.read(readBuf)) != -1) {
                    actualDigest.update(readBuf, 0, r);
                    totalRead += r;
                }
                assertEquals("Total bytes read should match", FILE_SIZE, totalRead);
                assertEquals("Read digest should match written digest",
                    toHex(expectedDigest.digest()),
                    toHex(actualDigest.digest()));
            }
            long endRead = System.currentTimeMillis();
            double readTimeSec = (endRead - startRead) / 1000.0;
            double readSpeed = (FILE_SIZE / 1024.0 / 1024.0) / readTimeSec;

            log.info("<<< Results ({}): Write: {} MB/s | Read: {} MB/s", mode, 
                String.format("%.2f", writeSpeed), String.format("%.2f", readSpeed));
            
            f.delete();
        }
    }

    private static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for ( byte b : data ) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
}
