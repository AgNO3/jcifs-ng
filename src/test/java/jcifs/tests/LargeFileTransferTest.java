package jcifs.tests;

import static org.junit.Assert.assertEquals;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
    private final int transportBufferSize;

    public LargeFileTransferTest(String name, Map<String, String> properties, int transportBufferSize) {
        super(name, properties);
        this.transportBufferSize = transportBufferSize;
    }

    @Parameters(name = "{0} - {2} bytes buffer")
    public static Collection<Object> configs() {
        List<Object> configs = new ArrayList<>();
        String dialectFilter = System.getProperty("largeFileTransfer.dialects", "smb2,smb30,smb31");
        String[] dialects = dialectFilter.split(",");
        String filter = System.getProperty("largeFileTransfer.bufferSizes", "65536,1048576");
        String[] parts = filter.split(",");
        int[] bufferSizes = new int[parts.length];
        for ( int i = 0; i < parts.length; i++ ) {
            bufferSizes[ i ] = Integer.parseInt(parts[ i ].trim());
        }

        for (Object baseObj : getConfigs(dialects)) {

            Object[] base = (Object[]) baseObj;
            for (int bufSize : bufferSizes) {
                configs.add(new Object[] { base[0] + "-" + bufSize, base[1], bufSize });
            }
        }
        return configs;
    }

    @Override
    @org.junit.Before
    public void setUp() throws Exception {
        if ( !getProperties().containsKey("jcifs.smb.client.maxVersion") ) {
            getProperties().put("jcifs.smb.client.maxVersion", "SMB311");
        }
        if ( !getProperties().containsKey("jcifs.smb.client.minVersion") ) {
            getProperties().put("jcifs.smb.client.minVersion", "SMB202");
        }
        getProperties().put("jcifs.smb.client.useSMB2Negotiation", "true");
        getProperties().put("jcifs.smb.client.dfs.disabled", "true");
        getProperties().put("jcifs.smb.client.ipcSigningEnforced", "false");
        getProperties().put("jcifs.smb.client.disablePlainTextPasswords", "false");
        getProperties().put("jcifs.smb.useRawNTLM", "true");
        
        // Set the transport buffer size for this run
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
            new Random().nextBytes(data);
            
            long startWrite = System.currentTimeMillis();
            try (OutputStream os = f.getOutputStream()) {
                int written = 0;
                while (written < FILE_SIZE) {
                    int toWrite = Math.min(data.length, FILE_SIZE - written);
                    os.write(data, 0, toWrite);
                    written += toWrite;
                }
            }
            long endWrite = System.currentTimeMillis();
            double writeTimeSec = (endWrite - startWrite) / 1000.0;
            double writeSpeed = (FILE_SIZE / 1024.0 / 1024.0) / writeTimeSec;

            long startRead = System.currentTimeMillis();
            try (InputStream is = f.getInputStream()) {
                byte[] readBuf = new byte[1024 * 1024];
                long totalRead = 0;
                int r;
                while ((r = is.read(readBuf)) != -1) {
                    totalRead += r;
                }
                assertEquals("Total bytes read should match", FILE_SIZE, totalRead);
            }
            long endRead = System.currentTimeMillis();
            double readTimeSec = (endRead - startRead) / 1000.0;
            double readSpeed = (FILE_SIZE / 1024.0 / 1024.0) / readTimeSec;

            log.info("<<< Results ({}): Write: {} MB/s | Read: {} MB/s", mode, 
                String.format("%.2f", writeSpeed), String.format("%.2f", readSpeed));
            
            f.delete();
        }
    }
}
