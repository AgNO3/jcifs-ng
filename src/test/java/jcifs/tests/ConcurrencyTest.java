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
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.SmbConstants;
import jcifs.SmbResource;
import jcifs.SmbSession;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.smb2.create.Smb2CloseRequest;
import jcifs.internal.smb2.create.Smb2CreateRequest;
import jcifs.smb.NtStatus;
import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;
import jcifs.smb.SmbFileOutputStream;
import jcifs.smb.SmbSessionInternal;
import jcifs.smb.SmbTransportInternal;
import jcifs.smb.SmbTreeInternal;
import jcifs.util.transport.TransportException;


/**
 * @author mbechler
 *
 */
@RunWith ( Parameterized.class )
@SuppressWarnings ( "javadoc" )
public class ConcurrencyTest extends BaseCIFSTest {

    static final Logger log = LoggerFactory.getLogger(ConcurrencyTest.class);
    private ExecutorService executor;


    public ConcurrencyTest ( String name, Map<String, String> properties ) {
        super(name, properties);
    }


    @Parameters ( name = "{0}" )
    public static Collection<Object> configs () {
        return getConfigs("smb1", "noNTStatus", "noNTSmbs", "smb2", "smb30", "smb31");
    }


    @Override
    @Before
    public void setUp () throws Exception {
        super.setUp();
        this.executor = Executors.newCachedThreadPool();
    }


    @After
    @Override
    public void tearDown () throws Exception {
        this.executor.shutdown();
        this.executor.awaitTermination(10, TimeUnit.SECONDS);
        super.tearDown();
    }


    @Test
    public void testExclusiveLock () throws InterruptedException, MalformedURLException, UnknownHostException {
        String fname = makeRandomName();
        try ( SmbFile sr = getDefaultShareRoot();
              SmbResource exclFile = new SmbFile(sr, fname) ) {
            ExclusiveLockFirst f = new ExclusiveLockFirst(exclFile);
            ExclusiveLockSecond s = new ExclusiveLockSecond(f, exclFile);

            List<MultiTestCase> runnables = new ArrayList<>();
            runnables.add(f);
            runnables.add(s);
            runMultiTestCase(runnables, 10);
        }
    }


    @Test
    public void testDeleteLocked () throws IOException {
        String fname = makeRandomName();
        try ( SmbFile sr = getDefaultShareRoot();
              SmbResource exclFile = new SmbFile(sr, fname) ) {

            try ( OutputStream s = exclFile.openOutputStream(false, SmbConstants.FILE_NO_SHARE) ) {
                try {
                    exclFile.delete();
                    fail("Could remove locked file");
                }
                catch ( SmbException e ) {
                    if ( e.getNtStatus() == NtStatus.NT_STATUS_SHARING_VIOLATION ) {
                        return;
                    }
                    throw e;
                }
            }
            finally {
                exclFile.delete();
            }
        }
    }


    @Test
    public void testOpenLocked () throws IOException {
        String fname = makeRandomName();
        try ( SmbFile sr = getDefaultShareRoot();
              SmbResource exclFile = new SmbFile(sr, fname) ) {

            try ( OutputStream s = exclFile.openOutputStream(false, SmbConstants.FILE_NO_SHARE);
                  InputStream is = exclFile.openInputStream(SmbConstants.FILE_NO_SHARE) ) {
                fail("No sharing violation");
            }
            catch ( SmbException e ) {
                if ( e.getNtStatus() == NtStatus.NT_STATUS_SHARING_VIOLATION ) {
                    return;
                }
                throw e;
            }
            finally {
                exclFile.delete();
            }
        }
    }


    @Test
    public void testOpenReadLocked () throws IOException {
        String fname = makeRandomName();
        try ( SmbFile sr = getDefaultShareRoot();
              SmbResource exclFile = new SmbFile(sr, fname) ) {

            exclFile.createNewFile();
            try {
                try ( InputStream is = exclFile.openInputStream(SmbConstants.FILE_NO_SHARE);
                      InputStream is2 = exclFile.openInputStream(SmbConstants.FILE_NO_SHARE) ) {
                    fail("No sharing violation");
                }
                catch ( SmbException e ) {
                    if ( e.getNtStatus() == NtStatus.NT_STATUS_SHARING_VIOLATION ) {
                        return;
                    }
                    throw e;
                }
            }
            finally {
                exclFile.delete();
            }
        }
    }

    private class ExclusiveLockFirst extends MultiTestCase {

        private Object startedLock = new Object();
        private volatile boolean started;

        private Object shutdownLock = new Object();
        private volatile boolean shutdown;
        private SmbResource file;


        /**
         * @param smbFile
         * 
         */
        public ExclusiveLockFirst ( SmbResource smbFile ) {
            this.file = smbFile;
        }


        public void waitForStart () throws InterruptedException {
            synchronized ( this.startedLock ) {
                while ( !this.started ) {
                    this.startedLock.wait();
                }
            }
        }


        public void shutdown () {
            this.shutdown = true;
            synchronized ( this.shutdownLock ) {
                this.shutdownLock.notify();
            }
        }


        /**
         * {@inheritDoc}
         *
         * @see java.lang.Runnable#run()
         */
        @Override
        public void run () {
            try {
                SmbResource f = this.file;
                f.createNewFile();
                try {
                    try ( OutputStream os = f.openOutputStream(false, SmbConstants.FILE_NO_SHARE) ) {
                        log.debug("Open1");
                        synchronized ( this.startedLock ) {
                            this.started = true;
                            this.startedLock.notify();
                        }
                        while ( !this.shutdown ) {
                            synchronized ( this.shutdownLock ) {
                                this.shutdownLock.wait();
                            }
                        }
                    }
                    catch ( InterruptedException e ) {
                        log.debug("Interrupted1", e);
                    }
                    log.debug("Closed1");
                    this.completed = true;
                }
                finally {
                    f.delete();
                }
            }
            catch ( Exception e ) {
                log.error("Test case failed", e);
            }
        }

    }


    @Test
    public void testInterrupt () throws UnknownHostException, IOException, InterruptedException {

        final Object lock = new Object();
        final Thread t = Thread.currentThread();

        this.executor.submit(new Runnable() {

            @Override
            public void run () {

                try {
                    synchronized ( lock ) {
                        lock.wait(1000);
                    }

                    Thread.sleep(100);
                    t.interrupt();
                }
                catch ( InterruptedException e ) {
                    e.printStackTrace();
                }
            }
        });

        try {
            CIFSContext c = getContext();
            c = withTestNTLMCredentials(c);
            try ( SmbTransportInternal trans = c.getTransportPool().getSmbTransport(c, getTestServer(), 0, false, true)
                    .unwrap(SmbTransportInternal.class);
                  SmbSession sess = trans.unwrap(SmbTransportInternal.class).getSmbSession(c, getTestServer(), null);
                  SmbTreeInternal tree = sess.unwrap(SmbSessionInternal.class).getSmbTree(getTestShare(), null).unwrap(SmbTreeInternal.class) ) {

                if ( trans.isSMB2() ) {
                    Smb2CreateRequest create = new Smb2CreateRequest(sess.getConfig(), "\\foocc");
                    create.setCreateDisposition(Smb2CreateRequest.FILE_OPEN_IF);
                    create.setRequestedOplockLevel(Smb2CreateRequest.SMB2_OPLOCK_LEVEL_BATCH);



                    try {
                        tree.send(create);

                        Smb2CreateRequest create2 = new Smb2CreateRequest(sess.getConfig(), "\\foocc");
                        create2.setOverrideTimeout(1000);
                        create2.setCreateDisposition(Smb2CreateRequest.FILE_OPEN_IF);
                        create2.setRequestedOplockLevel(Smb2CreateRequest.SMB2_OPLOCK_LEVEL_BATCH);

                        create2.chain(new Smb2CloseRequest(sess.getConfig(), Smb2Constants.UNSPECIFIED_FILEID));

                        synchronized ( lock ) {
                            lock.notify();
                        }
                        tree.send(create2);
                    }
                    catch ( Exception e ) {

                        if ( e.getCause() instanceof TransportException && e.getCause().getCause() instanceof InterruptedException ) {

                            Smb2CreateRequest create3 = new Smb2CreateRequest(sess.getConfig(), "\\xyz");
                            create3.setOverrideTimeout(1000);
                            create3.setCreateDisposition(Smb2CreateRequest.FILE_OPEN_IF);
                            create3.chain(new Smb2CloseRequest(sess.getConfig(), Smb2Constants.UNSPECIFIED_FILEID));
                        }
                        else {
                            e.printStackTrace();
                            fail("Failed to interrupt sendrecv");
                        }
                    }
                }
            }
        }
        finally {
            this.executor.shutdown();
            try {
                this.executor.awaitTermination(5, TimeUnit.SECONDS);
            } catch ( InterruptedException ignored ) {}
        }
    }

    private class ExclusiveLockSecond extends MultiTestCase {

        private ExclusiveLockFirst first;
        private SmbResource file;


        /**
         * @param f
         * @param smbFile
         */
        public ExclusiveLockSecond ( ExclusiveLockFirst f, SmbResource smbFile ) {
            this.first = f;
            this.file = smbFile;
        }


        /**
         * {@inheritDoc}
         *
         * @see java.lang.Runnable#run()
         */
        @Override
        public void run () {
            try {
                SmbResource f = this.file;
                this.first.waitForStart();
                try ( OutputStream os = f.openOutputStream(false, SmbConstants.FILE_NO_SHARE) ) {
                    log.debug("Open2");
                }
                catch ( IOException e ) {
                    if ( e instanceof SmbException && ( (SmbException) e ).getNtStatus() == NtStatus.NT_STATUS_SHARING_VIOLATION ) {
                        this.completed = true;
                        return;
                    }
                    throw e;
                }
                finally {
                    this.first.shutdown();
                }
            }
            catch ( Exception e ) {
                log.error("Test case failed", e);
            }
        }

    }


    @Test
    public void lockedWrites () throws InterruptedException, IOException {
        int n = 45;
        String fname = makeRandomName();

        try ( SmbFile sr = getDefaultShareRoot();
              SmbResource f = new SmbFile(sr, fname) ) {
            try {
                f.createNewFile();
                final AtomicInteger failCount = new AtomicInteger();
                final AtomicInteger writeCount = new AtomicInteger();
                List<MultiTestCase> runnables = new ArrayList<>();
                for ( int i = 0; i < n; i++ ) {
                    runnables.add(new LockedWritesTest(failCount, writeCount, new SmbFile(sr, fname)));
                }
                runMultiTestCase(runnables, 60);

                int readCnt = 0;
                try ( InputStream is = f.openInputStream(SmbConstants.FILE_NO_SHARE) ) {
                    while ( is.read() >= 0 ) {
                        readCnt++;
                    }
                }
                if ( log.isDebugEnabled() ) {
                    log.debug("Failures " + failCount.get() + " wrote " + writeCount.get() + " read " + readCnt);
                }
                assertEquals("Read less than we wrote", writeCount.get(), readCnt);
                assertEquals(n, failCount.get() + writeCount.get());
            }
            finally {
                f.delete();
            }
        }
    }

    private static class LockedWritesTest extends MultiTestCase {

        private final AtomicInteger failCount;
        private final SmbFile file;
        private AtomicInteger writeCount;


        /**
         * @param failCount
         * @param smbFile
         */
        public LockedWritesTest ( AtomicInteger failCount, AtomicInteger writeCount, SmbFile smbFile ) {
            this.failCount = failCount;
            this.writeCount = writeCount;
            this.file = smbFile;
        }


        /**
         * {@inheritDoc}
         *
         * @see java.lang.Runnable#run()
         */
        @Override
        public void run () {
            try ( SmbFileOutputStream out = this.file.openOutputStream(true, SmbConstants.FILE_NO_SHARE) ) {
                out.write(0xAA);
                this.writeCount.incrementAndGet();
                this.completed = true;
            }
            catch ( IOException e ) {
                if ( e instanceof SmbException && ( (SmbException) e ).getNtStatus() == NtStatus.NT_STATUS_SHARING_VIOLATION ) {
                    this.failCount.incrementAndGet();
                    this.completed = true;
                    return;
                }
                log.error("Unexpected error", e);
            }
            finally {
                try {
                    this.file.close();
                }
                catch ( Exception e ) {
                    log.error("Failed to close");
                }
            }
        }
    }


    @Test
    public void testMultiThread () throws InterruptedException {
        withTestNTLMCredentials(getContext());
        List<MutiThreadTestCase> runnables = new ArrayList<>();
        for ( int i = 0; i < 20; i++ ) {
            runnables.add(new MutiThreadTestCase());
        }
        runMultiTestCase(runnables, 60);
    }


    private void runMultiTestCase ( List<? extends MultiTestCase> testcases, int timeoutSecs ) throws InterruptedException {
        for ( Runnable r : testcases ) {
            this.executor.submit(r);
        }
        this.executor.shutdown();
        this.executor.awaitTermination(timeoutSecs, TimeUnit.SECONDS);
        for ( MultiTestCase r : testcases ) {
            assertTrue("Have not completed", r.completed);
        }
    }

    private static abstract class MultiTestCase implements Runnable {

        public MultiTestCase () {}

        boolean completed;
    }

    private class MutiThreadTestCase extends MultiTestCase {

        public MutiThreadTestCase () {}


        @Override
        public void run () {

            try {
                try ( SmbResource f = createTestFile() ) {
                    try {
                        // f.exists();
                        // try ( OutputStream os = f.openOutputStream(false, SmbConstants.FILE_NO_SHARE) ) {
                        // os.write(new byte[] {
                        // 1, 2, 3, 4, 5, 6, 7, 8
                        // });
                        // }
                        //
                        // try ( InputStream is = f.openInputStream(SmbConstants.FILE_NO_SHARE) ) {
                        // byte data[] = new byte[8];
                        // is.read(data);
                        // }
                    }
                    finally {
                        try {
                            f.delete();
                        }
                        catch ( IOException e ) {
                            System.err.println(f.getLocator().getUNCPath());
                            throw e;
                        }
                    }
                }
                this.completed = true;
            }
            catch (
                IOException |
                RuntimeException e ) {
                log.error("Test case failed", e);
            }
        }

    }
}
