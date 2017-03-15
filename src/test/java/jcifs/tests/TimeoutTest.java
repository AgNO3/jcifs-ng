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


import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URL;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.net.ServerSocketFactory;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import jcifs.CIFSContext;
import jcifs.config.DelegatingConfiguration;
import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;
import jcifs.smb.SmbSession;
import jcifs.smb.SmbTransport;
import jcifs.smb.SmbTransportPoolImpl;
import jcifs.smb.SmbTreeHandleImpl;
import jcifs.util.transport.ConnectionTimeoutException;


/**
 * @author mbechler
 *
 */
@RunWith ( Parameterized.class )
@SuppressWarnings ( "javadoc" )
public class TimeoutTest extends BaseCIFSTest {

    public TimeoutTest ( String name, Map<String, String> properties ) {
        super(name, properties);
    }


    protected CIFSContext lowTimeout ( CIFSContext ctx ) {
        return withConfig(ctx, new DelegatingConfiguration(ctx.getConfig()) {

            @Override
            public int getSoTimeout () {
                return 100;
            }


            @Override
            public boolean isIdleTimeoutDisabled () {
                return true;
            }
        });

    }


    protected CIFSContext fastIdle ( CIFSContext ctx ) {
        return withConfig(ctx, new DelegatingConfiguration(ctx.getConfig()) {

            @Override
            public int getSoTimeout () {
                return 1000;
            }


            @Override
            public int getConnTimeout () {
                return 1000;
            }


            @Override
            public int getSessionTimeout () {
                return 1000;
            }


            @Override
            public boolean isIdleTimeoutDisabled () {
                return false;
            }
        });

    }


    protected CIFSContext lowConnectTimeout ( CIFSContext ctx ) {
        return withConfig(ctx, new DelegatingConfiguration(ctx.getConfig()) {

            @Override
            public int getResponseTimeout () {
                return 100;
            }


            @Override
            public int getConnTimeout () {
                return 100;
            }
        });
    }


    @Test
    public void testTimeoutOpenFile () throws IOException, InterruptedException {
        // use separate context here as the settings stick to the transport
        CIFSContext ctx = lowTimeout(withTestNTLMCredentials(getNewContext()));
        SmbFile f = new SmbFile(new SmbFile(getTestShareURL(), ctx), makeRandomName());
        int soTimeout = ctx.getConfig().getSoTimeout();
        f.createNewFile();
        try {
            try ( OutputStream os = f.getOutputStream() ) {
                os.write(new byte[] {
                    1, 2, 3, 4, 5, 6, 7, 8
                });
            }

            try ( InputStream is = f.getInputStream() ) {
                for ( int i = 0; i < 8; i++ ) {
                    is.read();
                    Thread.sleep(soTimeout);
                }
            }
        }
        finally {
            f.delete();
        }
    }


    @Test
    public void testIdleTimeout () throws IOException, InterruptedException {
        // use separate context here as the settings stick to the transport
        CIFSContext ctx = fastIdle(withTestNTLMCredentials(getNewContext()));
        SmbFile f = new SmbFile(new SmbFile(getTestShareURL(), ctx), makeRandomName());
        int soTimeout = ctx.getConfig().getSoTimeout();
        f.createNewFile();
        try ( SmbTreeHandleImpl th = (SmbTreeHandleImpl) f.getTreeHandle() ) {
            Thread.sleep(2 * soTimeout);

            // connection should be closed by now
            SmbSession session = th.getSession();
            SmbTransport trans = session.getTransport();
            assertTrue("Transport is still connected", trans.isDisconnected());
            assertFalse("Connection is still in the pool", ( (SmbTransportPoolImpl) ctx.getTransportPool() ).contains(trans));
        }
        finally {
            f.delete();
        }
    }


    @Test ( expected = ConnectionTimeoutException.class )
    public void testConnectTimeoutRead () throws IOException {
        Set<Thread> threadsBefore = new HashSet<>(Thread.getAllStackTraces().keySet());
        try ( ServerSocket ss = ServerSocketFactory.getDefault().createServerSocket(0, -1, InetAddress.getLoopbackAddress()) ) {
            int port = ss.getLocalPort();
            InetAddress addr = ss.getInetAddress();

            long start = System.currentTimeMillis();
            CIFSContext ctx = lowConnectTimeout(getContext());
            SmbFile f = new SmbFile(new URL("smb", addr.getHostAddress(), port, "/" + getTestShare() + "/connect.test", ctx.getUrlHandler()), ctx);
            runConnectTimeoutTest(threadsBefore, start, ctx, f);
        }
    }


    @Test ( expected = ConnectionTimeoutException.class )
    public void testConnectTimeout () throws IOException {
        Set<Thread> threadsBefore = new HashSet<>(Thread.getAllStackTraces().keySet());
        long start = System.currentTimeMillis();
        CIFSContext ctx = lowConnectTimeout(getContext());

        SmbFile f = new SmbFile(new URL("smb", "10.255.255.1", 139, "/" + getTestShare() + "/connect.test", ctx.getUrlHandler()), ctx);
        runConnectTimeoutTest(threadsBefore, start, ctx, f);
    }


    /**
     * @param threadsBefore
     * @param start
     * @param ctx
     * @param f
     * @throws ConnectionTimeoutException
     * @throws SmbException
     */
    void runConnectTimeoutTest ( Set<Thread> threadsBefore, long start, CIFSContext ctx, SmbFile f ) throws ConnectionTimeoutException, SmbException {
        try {
            f.createNewFile();
            assertTrue("Did not see error", false);
        }
        catch ( SmbException e ) {
            if ( e.getCause() instanceof ConnectionTimeoutException ) {
                long timeout = System.currentTimeMillis() - start;
                assertTrue(
                    String.format(
                        "Timeout %d outside expected range (%f)",
                        timeout,
                        1.5 * ( ctx.getConfig().getConnTimeout() + ctx.getConfig().getResponseTimeout() )),
                    timeout < 1.5 * ( ctx.getConfig().getConnTimeout() + ctx.getConfig().getResponseTimeout() ));

                Set<Thread> threadsAfter = new HashSet<>(Thread.getAllStackTraces().keySet());
                threadsAfter.removeAll(threadsBefore);

                Set<Thread> leaked = new HashSet<>();
                for ( Thread t : threadsAfter ) {
                    if ( t.getName().startsWith("Transport") ) {
                        leaked.add(t);
                    }
                }
                assertTrue("Leaked transport threads, have " + leaked, leaked.size() == 0);
                throw (ConnectionTimeoutException) e.getCause();
            }
            throw e;
        }
    }

}
