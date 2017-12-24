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
import java.net.MalformedURLException;
import java.net.ServerSocket;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.net.ServerSocketFactory;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import jcifs.Address;
import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.NameServiceClient;
import jcifs.NetbiosAddress;
import jcifs.SmbResource;
import jcifs.config.DelegatingConfiguration;
import jcifs.context.CIFSContextWrapper;
import jcifs.netbios.UniAddress;
import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;
import jcifs.smb.SmbSessionInternal;
import jcifs.smb.SmbTransportInternal;
import jcifs.smb.SmbTransportPoolImpl;
import jcifs.smb.SmbTreeHandleInternal;
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


    @Parameters ( name = "{0}" )
    public static Collection<Object> configs () {
        return getConfigs("smb1", "smb2", "smb30", "smb31");
    }


    protected CIFSContext lowTimeout ( CIFSContext ctx ) {
        return withConfig(ctx, new DelegatingConfiguration(ctx.getConfig()) {

            @Override
            public int getSoTimeout () {
                return 100;
            }

        });

    }


    protected CIFSContext fastIdle ( CIFSContext ctx ) {
        return withConfig(ctx, new DelegatingConfiguration(ctx.getConfig()) {

            @Override
            public int getSoTimeout () {
                return 2000;
            }


            @Override
            public int getConnTimeout () {
                return 2000;
            }


            @Override
            public int getSessionTimeout () {
                return 2000;
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


    protected CIFSContext medConnectTimeout ( CIFSContext ctx ) {
        return withConfig(ctx, new DelegatingConfiguration(ctx.getConfig()) {

            @Override
            public int getResponseTimeout () {
                return 2000;
            }


            @Override
            public int getConnTimeout () {
                return 2000;
            }
        });
    }


    @Test
    public void testTimeoutOpenFile () throws IOException, InterruptedException {
        // use separate context here as the settings stick to the transport
        CIFSContext ctx = lowTimeout(withTestNTLMCredentials(getNewContext()));
        try ( SmbFile f = new SmbFile(new SmbFile(getTestShareURL(), ctx), makeRandomName()) ) {
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
    }


    @SuppressWarnings ( "resource" )
    @Test
    public void testIdleTimeout () throws IOException, InterruptedException {
        // use separate context here as the settings stick to the transport
        CIFSContext ctx = fastIdle(withTestNTLMCredentials(getNewContext()));
        try ( SmbFile r = new SmbFile(getTestShareURL(), ctx);
              SmbFile f = new SmbFile(r, makeRandomName()) ) {
            int soTimeout = ctx.getConfig().getSoTimeout();
            f.createNewFile();
            try {
                SmbTransportInternal t;
                try ( SmbTreeHandleInternal th = (SmbTreeHandleInternal) f.getTreeHandle();
                      SmbSessionInternal session = th.getSession().unwrap(SmbSessionInternal.class);
                      SmbTransportInternal trans = session.getTransport().unwrap(SmbTransportInternal.class) ) {
                    t = trans;
                }
                f.close();

                Thread.sleep(2 * soTimeout);

                // connection should be closed by now
                assertTrue("Transport is still connected", t.isDisconnected());
                assertFalse("Connection is still in the pool", ( (SmbTransportPoolImpl) ctx.getTransportPool() ).contains(t));
            }
            finally {
                f.delete();
            }
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
            try ( SmbResource f = new SmbFile(
                new URL("smb", addr.getHostAddress(), port, "/" + getTestShare() + "/connect.test", ctx.getUrlHandler()),
                ctx) ) {
                runConnectTimeoutTest(threadsBefore, start, ctx, f);
            }
        }
    }


    @Test ( expected = ConnectionTimeoutException.class )
    public void testConnectTimeout () throws IOException {
        Set<Thread> threadsBefore = new HashSet<>(Thread.getAllStackTraces().keySet());
        long start = System.currentTimeMillis();
        CIFSContext ctx = lowConnectTimeout(getContext());

        try ( SmbResource f = new SmbFile(new URL("smb", "10.255.255.1", 139, "/" + getTestShare() + "/connect.test", ctx.getUrlHandler()), ctx) ) {
            runConnectTimeoutTest(threadsBefore, start, ctx, f);
        }
    }


    /**
     * @param threadsBefore
     * @param start
     * @param ctx
     * @param f
     * @throws ConnectionTimeoutException
     * @throws SmbException
     */
    void runConnectTimeoutTest ( Set<Thread> threadsBefore, long start, CIFSContext ctx, SmbResource f )
            throws ConnectionTimeoutException, CIFSException {
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

    private static final class NSOverrideWrapper extends CIFSContextWrapper {

        private final NameServiceClient wrapper;


        NSOverrideWrapper ( CIFSContext delegate, NameServiceClient wrapper ) {
            super(delegate);
            this.wrapper = wrapper;
        }


        @Override
        protected CIFSContext wrap ( CIFSContext newContext ) {
            return new NSOverrideWrapper(super.wrap(newContext), this.wrapper);
        }


        @Override
        public NameServiceClient getNameServiceClient () {
            return this.wrapper;
        }
    }


    protected CIFSContext failHostInjecting ( CIFSContext ctx, final String replacement ) throws UnknownHostException {

        final NameServiceClient nscl = ctx.getNameServiceClient();

        final NameServiceClient wrapper = new DelegatingNameServiceClient(nscl) {

            private InetAddress replacementINET = InetAddress.getByName(replacement);
            private NetbiosAddress replacementNetbios = nscl.getNbtByName(replacement);


            @Override
            public Address[] getAllByName ( String hostname, boolean possibleNTDomainOrWorkgroup ) throws UnknownHostException {
                Address[] all = super.getAllByName(hostname, possibleNTDomainOrWorkgroup);
                return wrap(hostname, all);
            }


            @Override
            public Address getByName ( String hostname ) throws UnknownHostException {
                return wrap(hostname, super.getByName(hostname));
            }


            @Override
            public Address getByName ( String hostname, boolean possibleNTDomainOrWorkgroup ) throws UnknownHostException {
                return wrap(hostname, super.getByName(hostname, possibleNTDomainOrWorkgroup));
            }


            private Address wrap ( String hostname, Address byName ) {
                NetbiosAddress nbt = byName.unwrap(NetbiosAddress.class);
                if ( nbt != null ) {
                    return new UniAddress(this.replacementNetbios);
                }

                return new UniAddress(this.replacementINET);
            }


            private Address[] wrap ( String hostname, Address[] all ) {
                Address actual = all[ 0 ];
                NetbiosAddress nbt = actual.unwrap(NetbiosAddress.class);

                if ( nbt != null ) {
                    return new Address[] {
                        new UniAddress(this.replacementNetbios), actual
                    };
                }

                return new Address[] {
                    new UniAddress(this.replacementINET), actual
                };
            }
        };

        return new NSOverrideWrapper(ctx, wrapper);
    }


    @Test
    public void testMultiHostFailoverTimeout () throws MalformedURLException, CIFSException, UnknownHostException {
        // this could inject wrong DFS cache entries
        CIFSContext newContext = getNewContext();
        try ( SmbResource root = getDefaultShareRoot(failHostInjecting(medConnectTimeout(newContext), "10.255.255.1")) ) {
            root.exists();
        }
    }


    @Test
    public void testMultiHostFailover () throws MalformedURLException, CIFSException, UnknownHostException {
        // this could inject wrong DFS cache entries
        CIFSContext newContext = getNewContext();
        try ( SmbResource root = getDefaultShareRoot(failHostInjecting(medConnectTimeout(newContext), "0.0.0.0")) ) {
            root.exists();
        }
    }

}
