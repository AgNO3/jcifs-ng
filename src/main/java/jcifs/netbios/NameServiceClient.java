/* jcifs smb client library in Java
 * Copyright (C) 2000  "Michael B. Allen" <jcifs at samba dot org>
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

package jcifs.netbios;


import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.log4j.Logger;

import jcifs.CIFSContext;
import jcifs.ResolverType;
import jcifs.RuntimeCIFSException;
import jcifs.netbios.NbtAddress.CacheEntry;
import jcifs.util.Hexdump;


public class NameServiceClient implements Runnable {

    private static final int NAME_SERVICE_UDP_PORT = 137;

    private static final int FOREVER = -1;

    static final byte[] UNKNOWN_MAC_ADDRESS = new byte[] {
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
    };

    private static final Logger log = Logger.getLogger(NameServiceClient.class);

    private final Object LOCK = new Object();

    private final Map<Name, CacheEntry> addressCache = new HashMap<>();
    private final Set<Name> inFlightLookups = new HashSet<>();

    private int lport, closeTimeout;
    private byte[] snd_buf, rcv_buf;
    private DatagramSocket socket;
    private DatagramPacket in, out;
    private Map<Integer, NameServicePacket> responseTable = new HashMap<>();
    private Thread thread;
    private int nextNameTrnId = 0;
    private List<ResolverType> resolveOrder = new ArrayList<>();

    private InetAddress laddr, baddr;
    private CIFSContext transportContext;
    private NbtAddress localhostAddress;

    private Lmhosts lmhosts = new Lmhosts();
    private Name unknownName;
    private NbtAddress unknownAddress;


    public NameServiceClient ( CIFSContext tc ) {
        this(tc.getConfig().getNetbiosLocalPort(), tc.getConfig().getNetbiosLocalAddress(), tc);
    }


    NameServiceClient ( int lport, InetAddress laddr, CIFSContext tc ) {
        this.lport = lport;
        this.laddr = laddr;
        this.transportContext = tc;

        this.baddr = tc.getConfig().getBroadcastAddress();
        this.snd_buf = new byte[tc.getConfig().getNetbiosSndBufSize()];
        this.rcv_buf = new byte[tc.getConfig().getNetbiosRcvBufSize()];
        this.out = new DatagramPacket(this.snd_buf, tc.getConfig().getNetbiosSndBufSize(), this.baddr, NAME_SERVICE_UDP_PORT);
        this.in = new DatagramPacket(this.rcv_buf, tc.getConfig().getNetbiosRcvBufSize());
        this.resolveOrder = tc.getConfig().getResolveOrder();

        initCache(tc);
    }


    /**
     * 
     */
    private void initCache ( CIFSContext tc ) {
        this.unknownName = new Name(tc.getConfig(), "0.0.0.0", 0x00, null);
        this.unknownAddress = new NbtAddress(this.unknownName, 0, false, NbtAddress.B_NODE);
        this.addressCache.put(this.unknownName, new CacheEntry(this.unknownName, this.unknownAddress, FOREVER));

        /*
         * Determine the InetAddress of the local interface
         * if one was not specified.
         */
        InetAddress localInetAddress = tc.getConfig().getNetbiosLocalAddress();
        if ( localInetAddress == null ) {
            try {
                localInetAddress = InetAddress.getLocalHost();
            }
            catch ( UnknownHostException uhe ) {
                /*
                 * Java cannot determine the localhost. This is basically a config
                 * issue on the host. There's not much we can do about it. Just
                 * to suppress NPEs that would result we can create a possibly bogus
                 * address. Pretty sure the below cannot actually thrown a UHE tho.
                 */
                try {
                    localInetAddress = InetAddress.getByName("127.0.0.1");
                }
                catch ( UnknownHostException ignored ) {
                    throw new RuntimeCIFSException(ignored);
                }
            }
        }

        /*
         * If a local hostname was not provided a name like
         * JCIFS34_172_A6 will be dynamically generated for the
         * client. This is primarily (exclusively?) used as a
         * CallingName during session establishment.
         */
        String localHostname = tc.getConfig().getNetbiosHostname();
        if ( localHostname == null || localHostname.length() == 0 ) {
            byte[] addr = localInetAddress.getAddress();
            localHostname = "JCIFS" + ( addr[ 2 ] & 0xFF ) + "_" + ( addr[ 3 ] & 0xFF ) + "_"
                    + Hexdump.toHexString((int) ( Math.random() * 0xFF ), 2);
        }

        /*
         * Create an NbtAddress for the local interface with
         * the name deduced above possibly with scope applied and
         * cache it forever.
         */
        Name localName = new Name(tc.getConfig(), localHostname, 0x00, tc.getConfig().getNetbiosDefaultScope());
        this.localhostAddress = new NbtAddress(
            localName,
            localInetAddress.hashCode(),
            false,
            NbtAddress.B_NODE,
            false,
            false,
            true,
            false,
            UNKNOWN_MAC_ADDRESS);
        cacheAddress(localName, this.localhostAddress, FOREVER);
    }


    NbtAddress doNameQuery ( Name name, InetAddress svr, CIFSContext tc ) throws UnknownHostException {
        NbtAddress addr;

        if ( name.hexCode == 0x1d && svr == null ) {
            svr = tc.getNameServiceClient().baddr; // bit of a hack but saves a lookup
        }
        name.srcHashCode = svr != null ? svr.hashCode() : 0;
        addr = getCachedAddress(name);

        if ( addr == null ) {
            /*
             * This is almost exactly like InetAddress.java. See the
             * comments there for a description of how the LOOKUP_TABLE prevents
             * redundant queries from going out on the wire.
             */
            if ( ( addr = (NbtAddress) checkLookupTable(name) ) == null ) {
                try {
                    addr = tc.getNameServiceClient().getByName(name, svr, tc);
                }
                catch ( UnknownHostException uhe ) {
                    addr = this.unknownAddress;
                }
                finally {
                    cacheAddress(name, addr);
                    updateLookupTable(name);
                }
            }
        }
        if ( addr == this.unknownAddress ) {
            throw new UnknownHostException(name.toString());
        }
        return addr;
    }


    private Object checkLookupTable ( Name name ) {
        Object obj;

        synchronized ( this.inFlightLookups ) {
            if ( this.inFlightLookups.contains(name) == false ) {
                this.inFlightLookups.add(name);
                return null;
            }
            while ( this.inFlightLookups.contains(name) ) {
                try {
                    this.inFlightLookups.wait();
                }
                catch ( InterruptedException e ) {
                    log.trace("Interrupted", e);
                }
            }
        }
        obj = getCachedAddress(name);
        if ( obj == null ) {
            synchronized ( this.inFlightLookups ) {
                this.inFlightLookups.add(name);
            }
        }

        return obj;
    }


    private void updateLookupTable ( Name name ) {
        synchronized ( this.inFlightLookups ) {
            this.inFlightLookups.remove(name);
            this.inFlightLookups.notifyAll();
        }
    }


    void cacheAddress ( Name hostName, NbtAddress addr ) {
        if ( this.transportContext.getConfig().getNetbiosCachePolicy() == 0 ) {
            return;
        }
        long expiration = -1;
        if ( this.transportContext.getConfig().getNetbiosCachePolicy() != FOREVER ) {
            expiration = System.currentTimeMillis() + this.transportContext.getConfig().getNetbiosCachePolicy() * 1000;
        }
        cacheAddress(hostName, addr, expiration);
    }


    void cacheAddress ( Name hostName, NbtAddress addr, long expiration ) {
        if ( this.transportContext.getConfig().getNetbiosCachePolicy() == 0 ) {
            return;
        }
        synchronized ( this.addressCache ) {
            CacheEntry entry = this.addressCache.get(hostName);
            if ( entry == null ) {
                entry = new CacheEntry(hostName, addr, expiration);
                this.addressCache.put(hostName, entry);
            }
            else {
                entry.address = addr;
                entry.expiration = expiration;
            }
        }
    }


    void cacheAddressArray ( NbtAddress[] addrs ) {
        if ( this.transportContext.getConfig().getNetbiosCachePolicy() == 0 ) {
            return;
        }
        long expiration = -1;
        if ( this.transportContext.getConfig().getNetbiosCachePolicy() != FOREVER ) {
            expiration = System.currentTimeMillis() + this.transportContext.getConfig().getNetbiosCachePolicy() * 1000;
        }
        synchronized ( this.addressCache ) {
            for ( int i = 0; i < addrs.length; i++ ) {
                CacheEntry entry = this.addressCache.get(addrs[ i ].hostName);
                if ( entry == null ) {
                    entry = new CacheEntry(addrs[ i ].hostName, addrs[ i ], expiration);
                    this.addressCache.put(addrs[ i ].hostName, entry);
                }
                else {
                    entry.address = addrs[ i ];
                    entry.expiration = expiration;
                }
            }
        }
    }


    NbtAddress getCachedAddress ( Name hostName ) {
        if ( this.transportContext.getConfig().getNetbiosCachePolicy() == 0 ) {
            return null;
        }
        synchronized ( this.addressCache ) {
            CacheEntry entry = this.addressCache.get(hostName);
            if ( entry != null && entry.expiration < System.currentTimeMillis() && entry.expiration >= 0 ) {
                entry = null;
            }
            return entry != null ? entry.address : null;
        }
    }


    int getNextNameTrnId () {
        if ( ( ++this.nextNameTrnId & 0xFFFF ) == 0 ) {
            this.nextNameTrnId = 1;
        }
        return this.nextNameTrnId;
    }


    void ensureOpen ( int timeout ) throws IOException {
        this.closeTimeout = 0;
        if ( this.transportContext.getConfig().getNetbiosSoTimeout() != 0 ) {
            this.closeTimeout = Math.max(this.transportContext.getConfig().getNetbiosSoTimeout(), timeout);
        }
        // If socket is still good, the new closeTimeout will
        // be ignored; see tryClose comment.
        if ( this.socket == null ) {
            this.socket = new DatagramSocket(this.lport, this.laddr);
            this.thread = new Thread(this, "JCIFS-NameServiceClient");
            this.thread.setDaemon(true);
            this.thread.start();
        }
    }


    void tryClose () {
        synchronized ( this.LOCK ) {

            /*
             * Yes, there is the potential to drop packets
             * because we might close the socket during a
             * request. However the chances are slim and the
             * retry code should ensure the overall request
             * is serviced. The alternative complicates things
             * more than I think is worth it.
             */

            if ( this.socket != null ) {
                this.socket.close();
                this.socket = null;
            }
            this.thread = null;
            this.responseTable.clear();
        }
    }


    @Override
    public void run () {
        int nameTrnId;
        NameServicePacket response;

        try {
            while ( this.thread == Thread.currentThread() ) {
                this.in.setLength(this.transportContext.getConfig().getNetbiosRcvBufSize());

                this.socket.setSoTimeout(this.closeTimeout);
                this.socket.receive(this.in);

                log.trace("NetBIOS: new data read from socket");

                nameTrnId = NameServicePacket.readNameTrnId(this.rcv_buf, 0);
                response = this.responseTable.get(new Integer(nameTrnId));
                if ( response == null || response.received ) {
                    continue;
                }
                synchronized ( response ) {
                    response.readWireFormat(this.rcv_buf, 0);
                    response.received = true;

                    if ( log.isTraceEnabled() ) {
                        log.trace(response);
                        log.trace(Hexdump.toHexString(this.rcv_buf, 0, this.in.getLength()));
                    }

                    response.notify();
                }
            }
        }
        catch ( SocketTimeoutException ste ) {
            log.trace("Socket timeout", ste);
        }
        catch ( Exception ex ) {
            log.warn("Uncaught exception in NameServiceClient", ex);
        }
        finally {
            tryClose();
        }
    }


    void send ( NameServicePacket request, NameServicePacket response, int timeout ) throws IOException {
        Integer nid = null;
        int max = this.transportContext.getConfig().getWinsServers().length;

        if ( max == 0 )
            max = 1; /* No WINs, try only bcast addr */

        synchronized ( response ) {
            while ( max-- > 0 ) {
                try {
                    synchronized ( this.LOCK ) {
                        request.nameTrnId = getNextNameTrnId();
                        nid = new Integer(request.nameTrnId);

                        this.out.setAddress(request.addr);
                        this.out.setLength(request.writeWireFormat(this.snd_buf, 0));
                        response.received = false;

                        this.responseTable.put(nid, response);
                        ensureOpen(timeout + 1000);
                        this.socket.send(this.out);

                        if ( log.isTraceEnabled() ) {
                            log.trace(request);
                            log.trace(Hexdump.toHexString(this.snd_buf, 0, this.out.getLength()));
                        }
                    }

                    long start = System.currentTimeMillis();
                    while ( timeout > 0 ) {
                        response.wait(timeout);

                        /*
                         * JetDirect printer can respond to regular broadcast query
                         * with node status so we need to check to make sure that
                         * the record type matches the question type and if not,
                         * loop around and try again.
                         */
                        if ( response.received && request.questionType == response.recordType )
                            return;

                        response.received = false;
                        timeout -= System.currentTimeMillis() - start;
                    }

                }
                catch ( InterruptedException ie ) {
                    throw new IOException(ie.getMessage());
                }
                finally {
                    this.responseTable.remove(nid);
                }

                synchronized ( this.LOCK ) {
                    if ( NbtAddress.isWINS(this.transportContext, request.addr) == false )
                        break;
                    /*
                     * Message was sent to WINS but
                     * failed to receive response.
                     * Try a different WINS server.
                     */
                    if ( request.addr == NbtAddress.getWINSAddress(this.transportContext) )
                        NbtAddress.switchWINS(this.transportContext);
                    request.addr = NbtAddress.getWINSAddress(this.transportContext);
                }
            }
        }
    }


    NbtAddress[] getAllByName ( Name name, InetAddress addr ) throws UnknownHostException {
        int n;
        NameQueryRequest request = new NameQueryRequest(name);
        NameQueryResponse response = new NameQueryResponse();

        request.addr = addr != null ? addr : NbtAddress.getWINSAddress(this.transportContext);
        request.isBroadcast = request.addr == null;

        if ( request.isBroadcast ) {
            request.addr = this.baddr;
            n = this.transportContext.getConfig().getNetbiosRetryCount();
        }
        else {
            request.isBroadcast = false;
            n = 1;
        }

        do {
            try {
                send(request, response, this.transportContext.getConfig().getNetbiosRetryTimeout());
            }
            catch ( IOException ioe ) {
                log.info("Failed to send nameservice request for " + name.name, ioe);
                throw new UnknownHostException(name.name);
            }

            if ( response.received && response.resultCode == 0 ) {
                return response.addrEntry;
            }
        }
        while ( --n > 0 && request.isBroadcast );

        throw new UnknownHostException(name.name);
    }


    NbtAddress getByName ( Name name, InetAddress addr, CIFSContext tc ) throws UnknownHostException {
        int n;
        NameQueryRequest request = new NameQueryRequest(name);
        NameQueryResponse response = new NameQueryResponse();

        if ( addr != null ) { /*
                               * UniAddress calls always use this
                               * because it specifies addr
                               */
            request.addr = addr; /* if addr ends with 255 flag it bcast */
            request.isBroadcast = ( addr.getAddress()[ 3 ] == (byte) 0xFF );

            n = this.transportContext.getConfig().getNetbiosRetryCount();
            do {
                try {
                    send(request, response, this.transportContext.getConfig().getNetbiosRetryTimeout());
                }
                catch ( IOException ioe ) {
                    log.info("Failed to send nameservice request for " + name.name, ioe);
                    throw new UnknownHostException(name.name);
                }

                if ( response.received && response.resultCode == 0 ) {
                    int last = response.addrEntry.length - 1;
                    response.addrEntry[ last ].hostName.srcHashCode = addr.hashCode();
                    return response.addrEntry[ last ];
                }
            }
            while ( --n > 0 && request.isBroadcast );

            throw new UnknownHostException(name.name);
        }

        /*
         * If a target address to query was not specified explicitly
         * with the addr parameter we fall into this resolveOrder routine.
         */

        for ( ResolverType resolverType : this.resolveOrder ) {
            try {
                switch ( resolverType ) {
                case RESOLVER_LMHOSTS:
                    NbtAddress ans = this.lmhosts.getByName(name, tc);
                    if ( ans != null ) {
                        ans.hostName.srcHashCode = 0; // just has to be different
                                                      // from other methods
                        return ans;
                    }
                    break;
                case RESOLVER_WINS:
                case RESOLVER_BCAST:
                    if ( resolverType == ResolverType.RESOLVER_WINS && name.name != NbtAddress.MASTER_BROWSER_NAME && name.hexCode != 0x1d ) {
                        request.addr = NbtAddress.getWINSAddress(this.transportContext);
                        request.isBroadcast = false;
                    }
                    else {
                        request.addr = this.baddr;
                        request.isBroadcast = true;
                    }

                    n = this.transportContext.getConfig().getNetbiosRetryCount();
                    while ( n-- > 0 ) {
                        try {
                            send(request, response, this.transportContext.getConfig().getNetbiosRetryTimeout());
                        }
                        catch ( IOException ioe ) {
                            log.info("Failed to send nameservice request for " + name.name, ioe);
                            throw new UnknownHostException(name.name);
                        }
                        if ( response.received && response.resultCode == 0 ) {

                            /*
                             * Before we return, in anticipation of this address being cached we must
                             * augment the addresses name's hashCode to distinguish those resolved by
                             * Lmhosts, WINS, or BCAST. Otherwise a failed query from say WINS would
                             * get pulled out of the cache for a BCAST on the same name.
                             */
                            response.addrEntry[ 0 ].hostName.srcHashCode = request.addr.hashCode();
                            return response.addrEntry[ 0 ];
                        }
                        else if ( resolverType == ResolverType.RESOLVER_WINS ) {
                            /*
                             * If WINS reports negative, no point in retry
                             */
                            break;
                        }
                    }
                    break;
                default:
                    break;
                }
            }
            catch ( IOException ioe ) {
                log.debug("Failed to lookup name", ioe);
            }
        }
        throw new UnknownHostException(name.name);
    }


    NbtAddress[] getNodeStatus ( NbtAddress addr ) throws UnknownHostException {
        int n, srcHashCode;
        NodeStatusRequest request;
        NodeStatusResponse response;

        response = new NodeStatusResponse(this.transportContext.getConfig(), addr);
        request = new NodeStatusRequest(new Name(this.transportContext.getConfig(), NbtAddress.ANY_HOSTS_NAME, 0x00, null));
        request.addr = addr.getInetAddress();

        n = this.transportContext.getConfig().getNetbiosRetryCount();
        while ( n-- > 0 ) {
            try {
                send(request, response, this.transportContext.getConfig().getNetbiosRetryTimeout());
            }
            catch ( IOException ioe ) {
                log.info("Failed to send node status request for " + addr, ioe);
                throw new UnknownHostException(addr.toString());
            }
            if ( response.received && response.resultCode == 0 ) {

                /*
                 * For name queries resolved by different sources (e.g. WINS,
                 * BCAST, Node Status) we need to augment the hashcode generated
                 * for the addresses hostname or failed lookups for one type will
                 * be cached and cause other types to fail even though they may
                 * not be the authority for the name. For example, if a WINS lookup
                 * for FOO fails and caches unknownAddress for FOO, a subsequent
                 * lookup for FOO using BCAST should not fail because of that
                 * name cached from WINS.
                 *
                 * So, here we apply the source addresses hashCode to each name to
                 * make them specific to who resolved the name.
                 */

                srcHashCode = request.addr.hashCode();
                for ( int i = 0; i < response.addressArray.length; i++ ) {
                    response.addressArray[ i ].hostName.srcHashCode = srcHashCode;
                }
                return response.addressArray;
            }
        }
        throw new UnknownHostException(addr.hostName.name);
    }


    /**
     * @return
     */
    public NbtAddress getLocalHost () {
        return this.localhostAddress;
    }


    /**
     * @return
     */
    public Name getLocalName () {
        return this.localhostAddress.hostName;
    }


    /**
     * @return
     */
    public Lmhosts getLmhosts () {
        return this.lmhosts;
    }


    /**
     * @return
     */
    public Name getUnknownName () {
        return this.unknownName;
    }
}
