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
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import jcifs.smb.FileNotifyInformation;
import jcifs.smb.SmbException;
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

    private ExecutorService executor;
    private SmbFile base;
    private Future<List<FileNotifyInformation>> future;


    public WatchTest ( String name, Map<String, String> properties ) {
        super(name, properties);
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
        if ( this.base != null ) {
            this.base.close();
        }
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


    private void setupWatch ( int filter, boolean recursive ) throws InterruptedException {
        if ( this.future != null ) {
            this.future.cancel(true);
        }
        WatchRunnable task = new WatchRunnable(this.base, filter, recursive);
        this.future = this.executor.submit(task);
        Thread.sleep(1000);
    }


    @Test
    public void testWatchCreate () throws SmbException, MalformedURLException, UnknownHostException, InterruptedException, ExecutionException {
        try {
            setupWatch(FileNotifyInformation.FILE_NOTIFY_CHANGE_FILE_NAME, false);
            SmbFile cr = new SmbFile(this.base, "created");
            cr.createNewFile();
            assertNotified(FileNotifyInformation.FILE_ACTION_ADDED, "created", null);
        }
        catch ( TimeoutException e ) {
            Logger.getLogger(WatchTest.class).info("Timeout waiting", e);
            fail("Did not recieve notification");
        }
    }


    @Test
    public void testWatchModified () throws InterruptedException, ExecutionException, IOException {
        try {
            SmbFile cr = new SmbFile(this.base, "modified");
            cr.createNewFile();
            setupWatch(FileNotifyInformation.FILE_NOTIFY_CHANGE_ATTRIBUTES | FileNotifyInformation.FILE_NOTIFY_CHANGE_LAST_WRITE, false);
            try ( OutputStream os = cr.getOutputStream() ) {
                os.write(new byte[] {
                    1, 2, 3, 4
                });
            }
            assertNotified(FileNotifyInformation.FILE_ACTION_MODIFIED, "modified", null);
        }
        catch ( TimeoutException e ) {
            Logger.getLogger(WatchTest.class).info("Timeout waiting", e);
            fail("Did not recieve notification");
        }
    }


    @Test
    public void testWatchInBetween () throws InterruptedException, ExecutionException, IOException {
        try {
            setupWatch(FileNotifyInformation.FILE_NOTIFY_CHANGE_FILE_NAME, false);
            SmbFile cr = new SmbFile(this.base, "created");
            cr.createNewFile();
            assertNotified(FileNotifyInformation.FILE_ACTION_ADDED, "created", null);

            cr = new SmbFile(this.base, "created2");
            cr.createNewFile();

            setupWatch(FileNotifyInformation.FILE_NOTIFY_CHANGE_FILE_NAME, false);
            assertNotified(FileNotifyInformation.FILE_ACTION_ADDED, "created2", null);
        }
        catch ( TimeoutException e ) {
            Logger.getLogger(WatchTest.class).info("Timeout waiting", e);
            fail("Did not recieve notification");
        }
    }


    @Test
    public void testWatchClose () throws InterruptedException, ExecutionException, IOException {
        try {
            setupWatch(FileNotifyInformation.FILE_NOTIFY_CHANGE_ATTRIBUTES, false);
            this.base.close();
            Future<List<FileNotifyInformation>> f = this.future;
            assertNotNull(f);
            f.get(1, TimeUnit.SECONDS);
        }
        catch ( TimeoutException e ) {
            // this is not really expected but samba does not seem to properly handle this
            Assume.assumeTrue("Server did not react to close", false);
        }
    }


    private void assertNotified ( int action, String name, List<FileNotifyInformation> infos )
            throws InterruptedException, ExecutionException, TimeoutException {
        boolean found = checkInResult(action, name, infos);
        if ( !found ) {
            // retry, the first watch may have already come back before the triggered change was active
            try {
                setupWatch(action, name.indexOf('/') > 0);
                found = checkInResult(action, name, infos);
            }
            catch ( TimeoutException e ) {
                // might not recieve another notification
            }
        }
        if ( !found ) {
            Logger.getLogger(WatchTest.class).info("Notifications " + infos);
        }
        assertTrue("Notification found", found);
    }


    private boolean checkInResult ( int action, String name, List<FileNotifyInformation> infos )
            throws InterruptedException, ExecutionException, TimeoutException {
        assertNotNull(this.future);
        List<FileNotifyInformation> notifications = this.future.get(5, TimeUnit.SECONDS);
        if ( infos != null ) {
            infos.addAll(notifications);
        }
        boolean found = false;
        for ( FileNotifyInformation fi : notifications ) {
            if ( fi.action == action && fi.fileName.equals(name) ) {
                found = true;
            }
        }
        return found;
    }

    private static class WatchRunnable implements Callable<List<FileNotifyInformation>> {

        private SmbFile file;
        private int filter;
        private boolean recursive;


        public WatchRunnable ( SmbFile f, int filter, boolean recursive ) {
            this.file = f;
            this.filter = filter;
            this.recursive = recursive;
        }


        @Override
        public List<FileNotifyInformation> call () throws Exception {
            return this.file.watch(this.filter, this.recursive);
        }

    }
}
