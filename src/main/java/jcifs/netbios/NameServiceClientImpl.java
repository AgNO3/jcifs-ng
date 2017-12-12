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
import java.io.InterruptedIOException;
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.NameServiceClient;
import jcifs.NetbiosAddress;
import jcifs.ResolverType;
import jcifs.RuntimeCIFSException;
import jcifs.SmbConstants;
import jcifs.util.Hexdump;


/**
 * 
 * @author mbechler
 *
 */
public class NameServiceClientImpl implements Runnable, NameServiceClient {

    private static final int NAME_SERVICE_UDP_PORT = 137;

    static final byte[] UNKNOWN_MAC_ADDRESS = new byte[] {
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
    };

    private static final Logger log = LoggerFactory.getLogger(NameServiceClientImpl.class);

    private final Object LOCK = new Object();

    private int nbnsIndex = 0;

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


    /**
     * 
     * @param tc
     */
    public NameServiceClientImpl ( CIFSContext tc ) {
        this(tc.getConfig().getNetbiosLocalPort(), tc.getConfig().getNetbiosLocalAddress(), tc);
    }


    NameServiceClientImpl ( int lport, InetAddress laddr, CIFSContext tc ) {
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

    static final class CacheEntry {

        Name hostName;
        NbtAddress address;
        long expiration;


        CacheEntry ( Name hostName, NbtAddress address, long expiration ) {
            this.hostName = hostName;
            this.address = address;
            this.expiration = expiration;
        }
    }


    /**
     * 
     */
    private void initCache ( CIFSContext tc ) {
        this.unknownName = new Name(tc.getConfig(), "0.0.0.0", 0x00, null);
        this.unknownAddress = new NbtAddress(this.unknownName, 0, false, NbtAddress.B_NODE);
        this.addressCache.put(this.unknownName, new CacheEntry(this.unknownName, this.unknownAddress, SmbConstants.FOREVER));

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
        Name localName = new Name(tc.getConfig(), localHostname, 0x00, tc.getConfig().getNetbiosScope());
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
        cacheAddress(localName, this.localhostAddress, SmbConstants.FOREVER);
    }


    NbtAddress doNameQuery ( Name name, InetAddress svr ) throws UnknownHostException {
        NbtAddress addr;

        if ( name.hexCode == 0x1d && svr == null ) {
            svr = this.baddr; // bit of a hack but saves a lookup
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
                    addr = getByName(name, svr);
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
        if ( this.transportContext.getConfig().getNetbiosCachePolicy() != SmbConstants.FOREVER ) {
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
        if ( this.transportContext.getConfig().getNetbiosCachePolicy() != SmbConstants.FOREVER ) {
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
        try {
            while ( this.thread == Thread.currentThread() ) {
                this.in.setLength(this.transportContext.getConfig().getNetbiosRcvBufSize());

                this.socket.setSoTimeout(this.closeTimeout);
                this.socket.receive(this.in);

                log.trace("NetBIOS: new data read from socket");

                int nameTrnId = NameServicePacket.readNameTrnId(this.rcv_buf, 0);
                NameServicePacket response = this.responseTable.get(new Integer(nameTrnId));
                if ( response == null || response.received ) {
                    continue;
                }
                synchronized ( response ) {
                    response.readWireFormat(this.rcv_buf, 0);
                    response.received = true;

                    if ( log.isTraceEnabled() ) {
                        log.trace(response.toString());
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

        if ( max == 0 ) {
            max = 1; /* No WINs, try only bcast addr */
        }

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
                            log.trace(request.toString());
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
                    throw new InterruptedIOException();
                }
                finally {
                    this.responseTable.remove(nid);
                }

                synchronized ( this.LOCK ) {
                    if ( isWINS(request.addr) == false )
                        break;
                    /*
                     * Message was sent to WINS but
                     * failed to receive response.
                     * Try a different WINS server.
                     */
                    if ( request.addr == getWINSAddress() )
                        switchWINS();
                    request.addr = getWINSAddress();
                }
            }
        }
    }


    NbtAddress[] getAllByName ( Name name, InetAddress addr ) throws UnknownHostException {
        int n;
        Configuration config = this.transportContext.getConfig();
        NameQueryRequest request = new NameQueryRequest(config, name);
        NameQueryResponse response = new NameQueryResponse(config);

        request.addr = addr != null ? addr : getWINSAddress();
        request.isBroadcast = request.addr == null;

        if ( request.isBroadcast ) {
            request.addr = this.baddr;
            n = config.getNetbiosRetryCount();
        }
        else {
            request.isBroadcast = false;
            n = 1;
        }

        do {
            try {
                send(request, response, config.getNetbiosRetryTimeout());
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


    NbtAddress getByName ( Name name, InetAddress addr ) throws UnknownHostException {
        NameQueryRequest request = new NameQueryRequest(this.transportContext.getConfig(), name);
        NameQueryResponse response = new NameQueryResponse(this.transportContext.getConfig());

        if ( addr != null ) { /*
                               * UniAddress calls always use this
                               * because it specifies addr
                               */
            request.addr = addr; /* if addr ends with 255 flag it bcast */
            request.isBroadcast = ( addr.getAddress()[ 3 ] == (byte) 0xFF );

            int n = this.transportContext.getConfig().getNetbiosRetryCount();
            do {
                try {
                    send(request, response, this.transportContext.getConfig().getNetbiosRetryTimeout());
                }
                catch ( InterruptedIOException ioe ) {
                    if ( log.isTraceEnabled() ) {
                        log.trace("Timeout waiting for response " + name.name, ioe);
                    }
                    throw new UnknownHostException(name.name);
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
                    NbtAddress ans = this.lmhosts.getByName(name, this.transportContext);
                    if ( ans != null ) {
                        ans.hostName.srcHashCode = 0; // just has to be different
                                                      // from other methods
                        return ans;
                    }
                    break;
                case RESOLVER_WINS:
                case RESOLVER_BCAST:
                    if ( resolverType == ResolverType.RESOLVER_WINS && name.name != NbtAddress.MASTER_BROWSER_NAME && name.hexCode != 0x1d ) {
                        request.addr = getWINSAddress();
                        request.isBroadcast = false;
                    }
                    else {
                        request.addr = this.baddr;
                        request.isBroadcast = true;
                    }

                    int n = this.transportContext.getConfig().getNetbiosRetryCount();
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


    @Override
    public NbtAddress[] getNodeStatus ( NetbiosAddress addr ) throws UnknownHostException {
        NodeStatusResponse response = new NodeStatusResponse(this.transportContext.getConfig(), addr.unwrap(NbtAddress.class));
        NodeStatusRequest request = new NodeStatusRequest(
            this.transportContext.getConfig(),
            new Name(this.transportContext.getConfig(), NbtAddress.ANY_HOSTS_NAME, 0x00, null));
        request.addr = addr.toInetAddress();

        int n = this.transportContext.getConfig().getNetbiosRetryCount();
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

                int srcHashCode = request.addr.hashCode();
                for ( int i = 0; i < response.addressArray.length; i++ ) {
                    response.addressArray[ i ].hostName.srcHashCode = srcHashCode;
                }
                return response.addressArray;
            }
        }
        throw new UnknownHostException(addr.getHostName());
    }


    @Override
    public NbtAddress getNbtByName ( String host ) throws UnknownHostException {
        return getNbtByName(host, 0x00, null);
    }


    @Override
    public NbtAddress getNbtByName ( String host, int type, String scope ) throws UnknownHostException {
        return getNbtByName(host, type, scope, null);
    }


    @Override
    public NbtAddress getNbtByName ( String host, int type, String scope, InetAddress svr ) throws UnknownHostException {

        if ( host == null || host.length() == 0 ) {
            return getLocalHost();
        }

        Name name = new Name(this.transportContext.getConfig(), host, type, scope);
        if ( !Character.isDigit(host.charAt(0)) ) {
            return doNameQuery(name, svr);
        }

        int IP = 0x00;
        int hitDots = 0;
        char[] data = host.toCharArray();

        for ( int i = 0; i < data.length; i++ ) {
            char c = data[ i ];
            if ( c < 48 || c > 57 ) {
                return doNameQuery(name, svr);
            }
            int b = 0x00;
            while ( c != '.' ) {
                if ( c < 48 || c > 57 ) {
                    return doNameQuery(name, svr);
                }
                b = b * 10 + c - '0';

                if ( ++i >= data.length )
                    break;

                c = data[ i ];
            }
            if ( b > 0xFF ) {
                return doNameQuery(name, svr);
            }
            IP = ( IP << 8 ) + b;
            hitDots++;
        }
        if ( hitDots != 4 || host.endsWith(".") ) {
            return doNameQuery(name, svr);
        }
        return new NbtAddress(getUnknownName(), IP, false, NbtAddress.B_NODE);
    }


    @Override
    public NbtAddress[] getNbtAllByName ( String host, int type, String scope, InetAddress svr ) throws UnknownHostException {
        return getAllByName(new Name(this.transportContext.getConfig(), host, type, scope), svr);
    }


    @Override
    public NbtAddress[] getNbtAllByAddress ( String host ) throws UnknownHostException {
        return getNbtAllByAddress(getNbtByName(host, 0x00, null));
    }


    @Override
    public NbtAddress[] getNbtAllByAddress ( String host, int type, String scope ) throws UnknownHostException {
        return getNbtAllByAddress(getNbtByName(host, type, scope));
    }


    @Override
    public NbtAddress[] getNbtAllByAddress ( NetbiosAddress addr ) throws UnknownHostException {
        try {
            NbtAddress[] addrs = getNodeStatus(addr);
            cacheAddressArray(addrs);
            return addrs;
        }
        catch ( UnknownHostException uhe ) {
            throw new UnknownHostException(
                "no name with type 0x" + Hexdump.toHexString(addr.getNameType(), 2)
                        + ( ( ( addr.getName().getScope() == null ) || ( addr.getName().getScope().isEmpty() ) ) ? " with no scope"
                                : " with scope " + addr.getName().getScope() )
                        + " for host " + addr.getHostAddress());
        }
    }


    /**
     * 
     * @param tc
     * @return address of active WINS server
     */
    protected InetAddress getWINSAddress () {
        return this.transportContext.getConfig().getWinsServers().length == 0 ? null
                : this.transportContext.getConfig().getWinsServers()[ this.nbnsIndex ];
    }


    /**
     * 
     * @param svr
     * @return whether the given address is a WINS server
     */
    protected boolean isWINS ( InetAddress svr ) {
        for ( int i = 0; svr != null && i < this.transportContext.getConfig().getWinsServers().length; i++ ) {
            if ( svr.hashCode() == this.transportContext.getConfig().getWinsServers()[ i ].hashCode() ) {
                return true;
            }
        }
        return false;
    }


    protected InetAddress switchWINS () {
        this.nbnsIndex = ( this.nbnsIndex + 1 ) < this.transportContext.getConfig().getWinsServers().length ? this.nbnsIndex + 1 : 0;
        return this.transportContext.getConfig().getWinsServers().length == 0 ? null
                : this.transportContext.getConfig().getWinsServers()[ this.nbnsIndex ];
    }

    static class Sem {

        Sem ( int count ) {
            this.count = count;
        }

        int count;
    }

    static class QueryThread extends Thread {

        private Sem sem;
        private String host, scope;
        private int type;
        private NetbiosAddress ans = null;
        private InetAddress svr;
        private UnknownHostException uhe;
        private CIFSContext tc;


        QueryThread ( Sem sem, String host, int type, String scope, InetAddress svr, CIFSContext tc ) {
            super("JCIFS-QueryThread: " + host);
            this.sem = sem;
            this.host = host;
            this.type = type;
            this.scope = scope;
            this.svr = svr;
            this.tc = tc;
        }


        @Override
        public void run () {
            try {
                this.ans = this.tc.getNameServiceClient().getNbtByName(this.host, this.type, this.scope, this.svr);
            }
            catch ( UnknownHostException ex ) {
                this.uhe = ex;
            }
            catch ( Exception ex ) {
                this.uhe = new UnknownHostException(ex.getMessage());
            }
            finally {
                synchronized ( this.sem ) {
                    this.sem.count--;
                    this.sem.notify();
                }
            }
        }


        /**
         * @return the ans
         */
        public NetbiosAddress getAnswer () {
            return this.ans;
        }


        /**
         * @return the uhe
         */
        public UnknownHostException getException () {
            return this.uhe;
        }

    }


    NetbiosAddress lookupServerOrWorkgroup ( String name, InetAddress svr ) throws UnknownHostException {
        Sem sem = new Sem(2);
        int type = isWINS(svr) ? 0x1b : 0x1d;

        QueryThread q1x = new QueryThread(sem, name, type, null, svr, this.transportContext);
        QueryThread q20 = new QueryThread(sem, name, 0x20, null, svr, this.transportContext);
        q1x.setDaemon(true);
        q20.setDaemon(true);
        try {
            synchronized ( sem ) {
                q1x.start();
                q20.start();

                while ( sem.count > 0 && q1x.getAnswer() == null && q20.getAnswer() == null ) {
                    sem.wait();
                }
            }
        }
        catch ( InterruptedException ie ) {
            throw new UnknownHostException(name);
        }
        waitForQueryThreads(q1x, q20);
        if ( q1x.getAnswer() != null ) {
            return q1x.getAnswer();
        }
        else if ( q20.getAnswer() != null ) {
            return q20.getAnswer();
        }
        else {
            throw q1x.getException();
        }
    }


    private static void waitForQueryThreads ( QueryThread q1x, QueryThread q20 ) {
        interruptThreadSafely(q1x);
        joinThread(q1x);
        interruptThreadSafely(q20);
        joinThread(q20);
    }


    private static void interruptThreadSafely ( QueryThread thread ) {
        try {
            thread.interrupt();
        }
        catch ( SecurityException e ) {
            e.printStackTrace();
        }
    }


    private static void joinThread ( Thread thread ) {
        try {
            thread.join();
        }
        catch ( InterruptedException e ) {
            e.printStackTrace();
        }
    }


    private static boolean isAllDigits ( String hostname ) {
        for ( int i = 0; i < hostname.length(); i++ ) {
            if ( Character.isDigit(hostname.charAt(i)) == false ) {
                return false;
            }
        }
        return true;
    }


    @Override
    public UniAddress getByName ( String hostname ) throws UnknownHostException {
        return getByName(hostname, false);
    }


    @Override
    public UniAddress getByName ( String hostname, boolean possibleNTDomainOrWorkgroup ) throws UnknownHostException {
        return getAllByName(hostname, possibleNTDomainOrWorkgroup)[ 0 ];
    }


    @Override
    public UniAddress[] getAllByName ( String hostname, boolean possibleNTDomainOrWorkgroup ) throws UnknownHostException {
        Object addr;
        if ( hostname == null || hostname.length() == 0 ) {
            throw new UnknownHostException();
        }

        if ( UniAddress.isDotQuadIP(hostname) ) {
            return new UniAddress[] {
                new UniAddress(getNbtByName(hostname))
            };
        }

        if ( log.isTraceEnabled() ) {
            log.trace("Resolver order is " + this.transportContext.getConfig().getResolveOrder());
        }

        for ( ResolverType resolver : this.transportContext.getConfig().getResolveOrder() ) {
            try {
                switch ( resolver ) {
                case RESOLVER_LMHOSTS:
                    if ( ( addr = getLmhosts().getByName(hostname, this.transportContext) ) == null ) {
                        continue;
                    }
                    break;
                case RESOLVER_WINS:
                    if ( hostname.equals(NbtAddress.MASTER_BROWSER_NAME) || hostname.length() > 15 ) {
                        // invalid netbios name
                        continue;
                    }
                    if ( possibleNTDomainOrWorkgroup ) {
                        addr = lookupServerOrWorkgroup(hostname, getWINSAddress());
                    }
                    else {
                        addr = getNbtByName(hostname, 0x20, null, getWINSAddress());
                    }
                    break;
                case RESOLVER_BCAST:
                    if ( hostname.length() > 15 ) {
                        // invalid netbios name
                        continue;
                    }
                    if ( possibleNTDomainOrWorkgroup ) {
                        addr = lookupServerOrWorkgroup(hostname, this.transportContext.getConfig().getBroadcastAddress());
                    }
                    else {
                        addr = getNbtByName(hostname, 0x20, null, this.transportContext.getConfig().getBroadcastAddress());
                    }
                    break;
                case RESOLVER_DNS:
                    if ( isAllDigits(hostname) ) {
                        throw new UnknownHostException(hostname);
                    }
                    InetAddress[] iaddrs = InetAddress.getAllByName(hostname);
                    UniAddress[] addrs = new UniAddress[iaddrs.length];
                    for ( int ii = 0; ii < iaddrs.length; ii++ ) {
                        addrs[ ii ] = new UniAddress(iaddrs[ ii ]);
                    }
                    return addrs; // Success
                default:
                    throw new UnknownHostException(hostname);
                }
                UniAddress[] addrs = new UniAddress[1];
                addrs[ 0 ] = new UniAddress(addr);
                return addrs; // Success
            }
            catch ( IOException ioe ) {
                // Failure
            }
        }
        throw new UnknownHostException(hostname);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.NameServiceClient#getLocalHost()
     */
    @Override
    public NbtAddress getLocalHost () {
        return this.localhostAddress;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.NameServiceClient#getLocalName()
     */
    @Override
    public Name getLocalName () {
        if ( this.localhostAddress != null ) {
            return this.localhostAddress.hostName;
        }
        return null;
    }


    /**
     * 
     * @return lmhosts file used
     */
    public Lmhosts getLmhosts () {
        return this.lmhosts;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.NameServiceClient#getUnknownName()
     */
    @Override
    public Name getUnknownName () {
        return this.unknownName;
    }
}
