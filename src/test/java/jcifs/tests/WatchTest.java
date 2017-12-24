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


import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.UnknownHostException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSException;
import jcifs.FileNotifyInformation;
import jcifs.SmbResource;
import jcifs.SmbWatchHandle;
import jcifs.smb.SmbFile;


/**
 * 
 * 
 * Compatability notes:
 * - windows 2k12 will not trigger with FILE_NOTIFY_CHANGE_ATTRIBUTES if the file contents are modified (modtime
 * changes)
 * 
 * @author mbechler
 *
 */
@RunWith ( Parameterized.class )
@SuppressWarnings ( "javadoc" )
public class WatchTest extends BaseCIFSTest {

    private static final Logger log = LoggerFactory.getLogger(WatchTest.class);

    private ExecutorService executor;
    private SmbFile base;
    private Future<List<FileNotifyInformation>> future;


    public WatchTest ( String name, Map<String, String> properties ) {
        super(name, properties);
    }


    @Parameters ( name = "{0}" )
    public static Collection<Object> configs () {
        return getConfigs("smb1", "smb2", "smb30", "smb31");
    }


    @Override
    @Before
    public void setUp () throws Exception {
        super.setUp();
        this.executor = Executors.newSingleThreadExecutor();
        this.base = createTestDirectory();
    }


    @Override
    @After
    public void tearDown () throws Exception {
        if ( this.executor != null ) {
            this.executor.shutdown();
            if ( this.future != null ) {
                this.future.cancel(true);
            }
            this.executor.awaitTermination(1, TimeUnit.SECONDS);
        }
        if ( this.base != null ) {
            this.base.delete();
        }
        super.tearDown();
    }


    private void setupWatch ( SmbWatchHandle w ) throws InterruptedException {
        if ( this.future != null ) {
            this.future.cancel(true);
        }
        this.future = this.executor.submit(w);
        Thread.sleep(1000);
    }


    @Test
    public void testWatchCreate () throws CIFSException, MalformedURLException, UnknownHostException, InterruptedException, ExecutionException {
        try ( SmbWatchHandle w = this.base.watch(FileNotifyInformation.FILE_NOTIFY_CHANGE_FILE_NAME, false) ) {
            setupWatch(w);
            try ( SmbResource cr = new SmbFile(this.base, "created") ) {
                cr.createNewFile();
                assertNotified(w, FileNotifyInformation.FILE_ACTION_ADDED, "created", null);
            }
        }
        catch ( TimeoutException e ) {
            log.info("Timeout waiting", e);
            fail("Did not recieve notification");
        }
    }


    @Test
    public void testWatchModified () throws InterruptedException, ExecutionException, IOException {
        // samba 4 starting with some version does not seem to handle this correctly :(
        try ( SmbWatchHandle w = this.base
                .watch(FileNotifyInformation.FILE_NOTIFY_CHANGE_ATTRIBUTES | FileNotifyInformation.FILE_NOTIFY_CHANGE_LAST_WRITE, false) ) {
            try ( SmbFile cr = new SmbFile(this.base, "modified") ) {
                cr.createNewFile();
                setupWatch(w);
                try ( OutputStream os = cr.getOutputStream() ) {
                    os.write(new byte[] {
                        1, 2, 3, 4
                    });
                }
                assertNotified(w, FileNotifyInformation.FILE_ACTION_MODIFIED, "modified", null);
            }
        }
        catch ( TimeoutException e ) {
            log.info("Timeout waiting", e);
            fail("Did not recieve notification");
        }
    }


    @Test
    public void testWatchInBetween () throws InterruptedException, ExecutionException, IOException {
        try ( SmbWatchHandle w = this.base.watch(FileNotifyInformation.FILE_NOTIFY_CHANGE_FILE_NAME, false) ) {
            setupWatch(w);
            try ( SmbResource cr = new SmbFile(this.base, "created") ) {
                cr.createNewFile();
                assertNotified(w, FileNotifyInformation.FILE_ACTION_ADDED, "created", null);
            }

            try ( SmbResource cr = new SmbFile(this.base, "created2") ) {
                cr.createNewFile();
            }

            setupWatch(w);
            assertNotified(w, FileNotifyInformation.FILE_ACTION_ADDED, "created2", null);
        }
        catch ( TimeoutException e ) {
            log.info("Timeout waiting", e);
            fail("Did not recieve notification");
        }

    }


    @Test
    public void testWatchClose () throws InterruptedException, ExecutionException, IOException, TimeoutException {
        try ( SmbWatchHandle w = this.base.watch(FileNotifyInformation.FILE_NOTIFY_CHANGE_ATTRIBUTES, false) ) {
            setupWatch(w);
            w.close();
            Future<List<FileNotifyInformation>> f = this.future;
            assertNotNull(f);
            f.get(5, TimeUnit.SECONDS);
        }
    }


    @Test
    public void testWatchRecursive () throws InterruptedException, ExecutionException, IOException {
        try ( SmbResource subdir = this.base.resolve("test/") ) {
            subdir.mkdir();
            try ( SmbWatchHandle w = this.base.watch(FileNotifyInformation.FILE_NOTIFY_CHANGE_FILE_NAME, true) ) {
                setupWatch(w);
                try ( SmbResource cr = new SmbFile(subdir, "created") ) {
                    cr.createNewFile();
                    assertNotified(w, FileNotifyInformation.FILE_ACTION_ADDED, "test\\created", null);
                }
            }
            catch ( TimeoutException e ) {
                log.info("Timeout waiting", e);
                fail("Did not recieve notification");
            }
        }

    }


    private void assertNotified ( SmbWatchHandle w, int action, String name, List<FileNotifyInformation> infos )
            throws InterruptedException, ExecutionException, TimeoutException {
        boolean found = checkInResult(action, name, infos);
        if ( !found ) {
            // retry, the first watch may have already come back before the triggered change was active
            try {
                setupWatch(w);
                found = checkInResult(action, name, infos);
            }
            catch ( TimeoutException e ) {
                // might not recieve another notification
            }
        }
        if ( !found ) {
            log.info("Notifications " + infos);
        }
        assertTrue("No notification found", found);
    }


    private boolean checkInResult ( int action, String name, List<FileNotifyInformation> infos )
            throws InterruptedException, ExecutionException, TimeoutException {
        assertNotNull(this.future);
        List<FileNotifyInformation> notifications = this.future.get(10, TimeUnit.SECONDS);
        if ( infos != null ) {
            infos.addAll(notifications);
        }
        boolean found = false;
        for ( FileNotifyInformation fi : notifications ) {
            if ( fi.getAction() == action && fi.getFileName().equals(name) ) {
                found = true;
            }
        }
        return found;
    }

}
