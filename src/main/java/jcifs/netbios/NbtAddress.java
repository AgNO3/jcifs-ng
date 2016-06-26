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


import java.net.InetAddress;
import java.net.UnknownHostException;

import jcifs.CIFSContext;
import jcifs.util.Hexdump;


/**
 * This class represents a NetBIOS over TCP/IP address. Under normal
 * conditions, users of jCIFS need not be concerned with this class as
 * name resolution and session services are handled internally by the smb package.
 * 
 * <p>
 * Applications can use the methods <code>getLocalHost</code>,
 * <code>getByName</code>, and
 * <code>getAllByAddress</code> to create a new NbtAddress instance. This
 * class is symmetric with {@link java.net.InetAddress}.
 *
 * <p>
 * <b>About NetBIOS:</b> The NetBIOS name
 * service is a dynamic distributed service that allows hosts to resolve
 * names by broadcasting a query, directing queries to a server such as
 * Samba or WINS. NetBIOS is currently the primary networking layer for
 * providing name service, datagram service, and session service to the
 * Microsoft Windows platform. A NetBIOS name can be 15 characters long
 * and hosts usually registers several names on the network. From a
 * Windows command prompt you can see
 * what names a host registers with the nbtstat command.
 * <p>
 * <blockquote>
 * 
 * <pre>
 * C:\&gt;nbtstat -a 192.168.1.15
 * 
 *        NetBIOS Remote Machine Name Table
 * 
 *    Name               Type         Status
 * ---------------------------------------------
 * JMORRIS2        &lt;00&gt;  UNIQUE      Registered
 * BILLING-NY      &lt;00&gt;  GROUP       Registered
 * JMORRIS2        &lt;03&gt;  UNIQUE      Registered
 * JMORRIS2        &lt;20&gt;  UNIQUE      Registered
 * BILLING-NY      &lt;1E&gt;  GROUP       Registered
 * JMORRIS         &lt;03&gt;  UNIQUE      Registered
 * 
 * MAC Address = 00-B0-34-21-FA-3B
 * </pre>
 * 
 * </blockquote>
 * <p>
 * The hostname of this machine is <code>JMORRIS2</code>. It is
 * a member of the group(a.k.a workgroup and domain) <code>BILLING-NY</code>. To
 * obtain an {@link java.net.InetAddress} for a host one might do:
 *
 * <pre>
 * 
 * InetAddress addr = NbtAddress.getByName("jmorris2").getInetAddress();
 * </pre>
 * <p>
 * From a UNIX platform with Samba installed you can perform similar
 * diagnostics using the <code>nmblookup</code> utility.
 *
 * @author Michael B. Allen
 * @see java.net.InetAddress
 * @since jcifs-0.1
 */

public final class NbtAddress {

    /*
     * This is a special name that means all hosts. If you wish to find all hosts
     * on a network querying a workgroup group name is the preferred method.
     */

    static final String ANY_HOSTS_NAME = "*\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000";

    /**
     * This is a special name for querying the master browser that serves the
     * list of hosts found in "Network Neighborhood".
     */

    public static final String MASTER_BROWSER_NAME = "\u0001\u0002__MSBROWSE__\u0002";

    /**
     * A special generic name specified when connecting to a host for which
     * a name is not known. Not all servers respond to this name.
     */

    public static final String SMBSERVER_NAME = "*SMBSERVER     ";

    /**
     * A B node only broadcasts name queries. This is the default if a
     * nameserver such as WINS or Samba is not specified.
     */

    public static final int B_NODE = 0;

    /**
     * A Point-to-Point node, or P node, unicasts queries to a nameserver
     * only. Natrually the <code>jcifs.netbios.nameserver</code> property must
     * be set.
     */

    public static final int P_NODE = 1;

    /**
     * Try Broadcast queries first, then try to resolve the name using the
     * nameserver.
     */

    public static final int M_NODE = 2;

    /**
     * A Hybrid node tries to resolve a name using the nameserver first. If
     * that fails use the broadcast address. This is the default if a nameserver
     * is provided. This is the behavior of Microsoft Windows machines.
     */

    public static final int H_NODE = 3;

    private static int nbnsIndex = 0;

    static final byte[] UNKNOWN_MAC_ADDRESS = new byte[] {
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
    };

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
     * Determines the address of a host given it's host name. The name can be a NetBIOS name like
     * "freto" or an IP address like "192.168.1.15". It cannot be a DNS name;
     * the analygous {@link jcifs.UniAddress} or {@link java.net.InetAddress}
     * <code>getByName</code> methods can be used for that.
     *
     * @param host
     *            hostname to resolve
     * @param tc
     *            context to use
     * @return the resolved address
     * @throws java.net.UnknownHostException
     *             if there is an error resolving the name
     */

    public static NbtAddress getByName ( String host, CIFSContext tc ) throws UnknownHostException {
        return getByName(host, 0x00, null, tc);
    }


    /**
     * Determines the address of a host given it's host name. NetBIOS
     * names also have a <code>type</code>. Types(aka Hex Codes)
     * are used to distiquish the various services on a host. <a
     * href="../../../nbtcodes.html">Here</a> is
     * a fairly complete list of NetBIOS hex codes. Scope is not used but is
     * still functional in other NetBIOS products and so for completeness it has been
     * implemented. A <code>scope</code> of <code>null</code> or <code>""</code>
     * signifies no scope.
     *
     * @param host
     *            the name to resolve
     * @param type
     *            the hex code of the name
     * @param scope
     *            the scope of the name
     * @param tc
     *            context to use
     * @return the resolved address
     * @throws java.net.UnknownHostException
     *             if there is an error resolving the name
     */
    public static NbtAddress getByName ( String host, int type, String scope, CIFSContext tc ) throws UnknownHostException {
        return getByName(host, type, scope, null, tc);
    }


    /**
     * Determines the address of a host given it's host name. NetBIOS
     * names also have a <code>type</code>. Types(aka Hex Codes)
     * are used to distiquish the various services on a host. <a
     * href="../../../nbtcodes.html">Here</a> is
     * a fairly complete list of NetBIOS hex codes. Scope is not used but is
     * still functional in other NetBIOS products and so for completeness it has been
     * implemented. A <code>scope</code> of <code>null</code> or <code>""</code>
     * signifies no scope.
     * 
     * The additional <code>svr</code> parameter specifies the address to
     * query. This might be the address of a specific host, a name server,
     * or a broadcast address.
     *
     * @param host
     *            the name to resolve
     * @param type
     *            the hex code of the name
     * @param scope
     *            the scope of the name
     * @param svr
     *            server to query
     * @param tc
     *            context to use
     * @return the resolved address
     * @throws java.net.UnknownHostException
     *             if there is an error resolving the name
     */
    public static NbtAddress getByName ( String host, int type, String scope, InetAddress svr, CIFSContext tc ) throws UnknownHostException {

        if ( host == null || host.length() == 0 ) {
            return tc.getNameServiceClient().getLocalHost();
        }
        Name name = new Name(tc.getConfig(), host, type, scope);
        if ( !Character.isDigit(host.charAt(0)) ) {
            return tc.getNameServiceClient().doNameQuery(name, svr, tc);
        }

        int IP = 0x00;
        int hitDots = 0;
        char[] data = host.toCharArray();

        for ( int i = 0; i < data.length; i++ ) {
            char c = data[ i ];
            if ( c < 48 || c > 57 ) {
                return tc.getNameServiceClient().doNameQuery(name, svr, tc);
            }
            int b = 0x00;
            while ( c != '.' ) {
                if ( c < 48 || c > 57 ) {
                    return tc.getNameServiceClient().doNameQuery(name, svr, tc);
                }
                b = b * 10 + c - '0';

                if ( ++i >= data.length )
                    break;

                c = data[ i ];
            }
            if ( b > 0xFF ) {
                return tc.getNameServiceClient().doNameQuery(name, svr, tc);
            }
            IP = ( IP << 8 ) + b;
            hitDots++;
        }
        if ( hitDots != 4 || host.endsWith(".") ) {
            return tc.getNameServiceClient().doNameQuery(name, svr, tc);
        }
        return new NbtAddress(tc.getNameServiceClient().getUnknownName(), IP, false, B_NODE);
    }


    /**
     * Retrieve all addresses of a host by it's name.
     * 
     * @param host
     *            hostname to lookup all addresses for
     * @param type
     *            the hexcode of the name
     * @param scope
     *            the scope of the name
     * @param svr
     *            server to query
     * @param tc
     *            context to use
     * 
     * @return the resolved addresses
     * @throws UnknownHostException
     */
    public static NbtAddress[] getAllByName ( String host, int type, String scope, InetAddress svr, CIFSContext tc ) throws UnknownHostException {
        return tc.getNameServiceClient().getAllByName(new Name(tc.getConfig(), host, type, scope), svr);
    }


    /**
     * Retrieve all addresses of a host by it's address. NetBIOS hosts can
     * have many names for a given IP address. The name and IP address make the
     * NetBIOS address. This provides a way to retrieve the other names for a
     * host with the same IP address.
     *
     * @param host
     *            hostname to lookup all addresses for
     * @param tc
     *            context to use
     * @return resolved addresses
     * @throws java.net.UnknownHostException
     *             if there is an error resolving the name
     */

    public static NbtAddress[] getAllByAddress ( String host, CIFSContext tc ) throws UnknownHostException {
        return getAllByAddress(getByName(host, 0x00, null, tc), tc);
    }


    /**
     * Retrieve all addresses of a host by it's address. NetBIOS hosts can
     * have many names for a given IP address. The name and IP address make
     * the NetBIOS address. This provides a way to retrieve the other names
     * for a host with the same IP address. See {@link #getByName}
     * for a description of <code>type</code>
     * and <code>scope</code>.
     *
     * @param host
     *            hostname to lookup all addresses for
     * @param type
     *            the hexcode of the name
     * @param scope
     *            the scope of the name
     * @param tc
     *            context to use
     * @return resolved addresses
     * @throws java.net.UnknownHostException
     *             if there is an error resolving the name
     */

    public static NbtAddress[] getAllByAddress ( String host, int type, String scope, CIFSContext tc ) throws UnknownHostException {
        return getAllByAddress(getByName(host, type, scope, tc), tc);
    }


    /**
     * Retrieve all addresses of a host by it's address. NetBIOS hosts can
     * have many names for a given IP address. The name and IP address make the
     * NetBIOS address. This provides a way to retrieve the other names for a
     * host with the same IP address.
     *
     * @param addr
     *            the address to query
     * @param tc
     *            context to use
     * @return resolved addresses
     * @throws UnknownHostException
     *             if address cannot be resolved
     */

    public static NbtAddress[] getAllByAddress ( NbtAddress addr, CIFSContext tc ) throws UnknownHostException {
        try {
            NbtAddress[] addrs = tc.getNameServiceClient().getNodeStatus(addr);
            tc.getNameServiceClient().cacheAddressArray(addrs);
            return addrs;
        }
        catch ( UnknownHostException uhe ) {
            throw new UnknownHostException(
                "no name with type 0x" + Hexdump.toHexString(addr.hostName.hexCode, 2)
                        + ( ( ( addr.hostName.scope == null ) || ( addr.hostName.scope.length() == 0 ) ) ? " with no scope"
                                : " with scope " + addr.hostName.scope )
                        + " for host " + addr.getHostAddress());
        }
    }


    /**
     * 
     * @param tc
     * @return address of active WINS server
     */
    public static InetAddress getWINSAddress ( CIFSContext tc ) {
        return tc.getConfig().getWinsServers().length == 0 ? null : tc.getConfig().getWinsServers()[ nbnsIndex ];
    }


    /**
     * 
     * @param tc
     * @param svr
     * @return whether the given address is a WINS server
     */
    public static boolean isWINS ( CIFSContext tc, InetAddress svr ) {
        for ( int i = 0; svr != null && i < tc.getConfig().getWinsServers().length; i++ ) {
            if ( svr.hashCode() == tc.getConfig().getWinsServers()[ i ].hashCode() ) {
                return true;
            }
        }
        return false;
    }


    static InetAddress switchWINS ( CIFSContext tc ) {
        nbnsIndex = ( nbnsIndex + 1 ) < tc.getConfig().getWinsServers().length ? nbnsIndex + 1 : 0;
        return tc.getConfig().getWinsServers().length == 0 ? null : tc.getConfig().getWinsServers()[ nbnsIndex ];
    }

    Name hostName;
    int address, nodeType;
    boolean groupName, isBeingDeleted, isInConflict, isActive, isPermanent, isDataFromNodeStatus;
    byte[] macAddress;
    String calledName;


    NbtAddress ( Name hostName, int address, boolean groupName, int nodeType ) {
        this.hostName = hostName;
        this.address = address;
        this.groupName = groupName;
        this.nodeType = nodeType;
    }


    NbtAddress ( Name hostName, int address, boolean groupName, int nodeType, boolean isBeingDeleted, boolean isInConflict, boolean isActive,
            boolean isPermanent, byte[] macAddress ) {

        /*
         * The NodeStatusResponse.readNodeNameArray method may also set this
         * information. These two places where node status data is populated should
         * be consistent. Be carefull!
         */
        this.hostName = hostName;
        this.address = address;
        this.groupName = groupName;
        this.nodeType = nodeType;
        this.isBeingDeleted = isBeingDeleted;
        this.isInConflict = isInConflict;
        this.isActive = isActive;
        this.isPermanent = isPermanent;
        this.macAddress = macAddress;
        this.isDataFromNodeStatus = true;
    }


    /**
     * Guess next called name to try for session establishment. These
     * methods are used by the smb package.
     * 
     * @return guessed name
     */
    public String firstCalledName () {

        this.calledName = this.hostName.name;

        if ( Character.isDigit(this.calledName.charAt(0)) ) {
            int i, len, dots;
            char[] data;

            i = dots = 0; /* quick IP address validation */
            len = this.calledName.length();
            data = this.calledName.toCharArray();
            while ( i < len && Character.isDigit(data[ i++ ]) ) {
                if ( i == len && dots == 3 ) {
                    // probably an IP address
                    this.calledName = SMBSERVER_NAME;
                    break;
                }
                if ( i < len && data[ i ] == '.' ) {
                    dots++;
                    i++;
                }
            }
        }
        else {
            switch ( this.hostName.hexCode ) {
            case 0x1B:
            case 0x1C:
            case 0x1D:
                this.calledName = SMBSERVER_NAME;
            }
        }

        return this.calledName;
    }


    /**
     * 
     * @param tc
     *            context to use
     * @return net name to try
     */
    public String nextCalledName ( CIFSContext tc ) {

        if ( this.calledName == this.hostName.name ) {
            this.calledName = SMBSERVER_NAME;
        }
        else if ( SMBSERVER_NAME.equals(this.calledName) ) {
            NbtAddress[] addrs;

            try {
                addrs = tc.getNameServiceClient().getNodeStatus(this);
                if ( this.hostName.hexCode == 0x1D ) {
                    for ( int i = 0; i < addrs.length; i++ ) {
                        if ( addrs[ i ].hostName.hexCode == 0x20 ) {
                            return addrs[ i ].hostName.name;
                        }
                    }
                    return null;
                }
                else if ( this.isDataFromNodeStatus ) {
                    /*
                     * 'this' has been updated and should now
                     * have a real NetBIOS name
                     */
                    this.calledName = null;
                    return this.hostName.name;
                }
            }
            catch ( UnknownHostException uhe ) {
                this.calledName = null;
            }
        }
        else {
            this.calledName = null;
        }

        return this.calledName;
    }


    /*
     * There are three degrees of state that any NbtAddress can have.
     * 
     * 1) IP Address - If a dot-quad IP string is used with getByName (or used
     * to create an NbtAddress internal to this netbios package), no query is
     * sent on the wire and the only state this object has is it's IP address
     * (but that's enough to connect to a host using *SMBSERVER for CallingName).
     * 
     * 2) IP Address, NetBIOS name, nodeType, groupName - If however a
     * legal NetBIOS name string is used a name query request will retreive
     * the IP, node type, and whether or not this NbtAddress represents a
     * group name. This degree of state can be obtained with a Name Query
     * Request or Node Status Request.
     * 
     * 3) All - The NbtAddress will be populated with all state such as mac
     * address, isPermanent, isBeingDeleted, ...etc. This information can only
     * be retrieved with the Node Status request.
     * 
     * The degree of state that an NbtAddress has is dependant on how it was
     * created and what is required of it. The second degree of state is the
     * most common. This is the state information that would be retrieved from
     * WINS for example. Natrually it is not practical for every NbtAddress
     * to be populated will all state requiring a Node Status on every host
     * encountered. The below methods allow state to be populated when requested
     * in a lazy fashon.
     */

    void checkData ( CIFSContext tc ) throws UnknownHostException {
        if ( this.hostName.isUnknown() ) {
            getAllByAddress(this, tc);
        }
    }


    void checkNodeStatusData ( CIFSContext tc ) throws UnknownHostException {
        if ( this.isDataFromNodeStatus == false ) {
            getAllByAddress(this, tc);
        }
    }


    /**
     * Determines if the address is a group address. This is also
     * known as a workgroup name or group name.
     * 
     * @param tc
     *            context to use
     * @return whether the given address is a group address
     *
     * @throws UnknownHostException
     *             if the host cannot be resolved to find out.
     */

    public boolean isGroupAddress ( CIFSContext tc ) throws UnknownHostException {
        checkData(tc);
        return this.groupName;
    }


    /**
     * Checks the node type of this address.
     * 
     * @param tc
     *            context to use
     * @return {@link jcifs.netbios.NbtAddress#B_NODE},
     *         {@link jcifs.netbios.NbtAddress#P_NODE}, {@link jcifs.netbios.NbtAddress#M_NODE},
     *         {@link jcifs.netbios.NbtAddress#H_NODE}
     *
     * @throws UnknownHostException
     *             if the host cannot be resolved to find out.
     */

    public int getNodeType ( CIFSContext tc ) throws UnknownHostException {
        checkData(tc);
        return this.nodeType;
    }


    /**
     * Determines if this address in the process of being deleted.
     * 
     * @param tc
     *            context to use
     * @return whether this address is in the process of being deleted
     *
     * @throws UnknownHostException
     *             if the host cannot be resolved to find out.
     */

    public boolean isBeingDeleted ( CIFSContext tc ) throws UnknownHostException {
        checkNodeStatusData(tc);
        return this.isBeingDeleted;
    }


    /**
     * Determines if this address in conflict with another address.
     *
     * @param tc
     *            context to use
     * @return whether this address is in conflict with another address
     * @throws UnknownHostException
     *             if the host cannot be resolved to find out.
     */

    public boolean isInConflict ( CIFSContext tc ) throws UnknownHostException {
        checkNodeStatusData(tc);
        return this.isInConflict;
    }


    /**
     * Determines if this address is active.
     * 
     * @param tc
     *            context to use
     * @return whether this adress is active
     *
     * @throws UnknownHostException
     *             if the host cannot be resolved to find out.
     */

    public boolean isActive ( CIFSContext tc ) throws UnknownHostException {
        checkNodeStatusData(tc);
        return this.isActive;
    }


    /**
     * Determines if this address is set to be permanent.
     * 
     * @param tc
     *            context to use
     * @return whether this address is permanent
     *
     * @throws UnknownHostException
     *             if the host cannot be resolved to find out.
     */

    public boolean isPermanent ( CIFSContext tc ) throws UnknownHostException {
        checkNodeStatusData(tc);
        return this.isPermanent;
    }


    /**
     * Retrieves the MAC address of the remote network interface. Samba returns all zeros.
     * 
     * @param tc
     *            context to use
     *
     * @return the MAC address as an array of six bytes
     * @throws UnknownHostException
     *             if the host cannot be resolved to
     *             determine the MAC address.
     */

    public byte[] getMacAddress ( CIFSContext tc ) throws UnknownHostException {
        checkNodeStatusData(tc);
        return this.macAddress;
    }


    /**
     * The hostname of this address. If the hostname is null the local machines
     * IP address is returned.
     *
     * @return the text representation of the hostname associated with this address
     */

    public String getHostName () {
        /*
         * 2010 - We no longer try a Node Status to get the
         * hostname because apparently some servers do not respond
         * anymore. I think everyone post Windows 98 will accept
         * an IP address as the tconHostName which is the principal
         * use of this method.
         */
        if ( this.hostName.isUnknown() ) {
            return getHostAddress();
        }
        return this.hostName.name;
    }


    /**
     * Returns the raw IP address of this NbtAddress. The result is in network
     * byte order: the highest order byte of the address is in getAddress()[0].
     *
     * @return a four byte array
     */

    public byte[] getAddress () {
        byte[] addr = new byte[4];

        addr[ 0 ] = (byte) ( ( this.address >>> 24 ) & 0xFF );
        addr[ 1 ] = (byte) ( ( this.address >>> 16 ) & 0xFF );
        addr[ 2 ] = (byte) ( ( this.address >>> 8 ) & 0xFF );
        addr[ 3 ] = (byte) ( this.address & 0xFF );
        return addr;
    }


    /**
     * To convert this address to an <code>InetAddress</code>.
     *
     * @return the {@link java.net.InetAddress} representation of this address.
     * @throws UnknownHostException
     */

    public InetAddress getInetAddress () throws UnknownHostException {
        return InetAddress.getByName(getHostAddress());
    }


    /**
     * Returns this IP adress as a {@link java.lang.String} in the form "%d.%d.%d.%d".
     * 
     * @return string representation of the IP address
     */

    public String getHostAddress () {
        return ( ( this.address >>> 24 ) & 0xFF ) + "." + ( ( this.address >>> 16 ) & 0xFF ) + "." + ( ( this.address >>> 8 ) & 0xFF ) + "."
                + ( ( this.address >>> 0 ) & 0xFF );
    }


    /**
     * Returned the hex code associated with this name(e.g. 0x20 is for the file service)
     * 
     * @return the name type
     */

    public int getNameType () {
        return this.hostName.hexCode;
    }


    /**
     * Returns a hashcode for this IP address. The hashcode comes from the IP address
     * and is not generated from the string representation. So because NetBIOS nodes
     * can have many names, all names associated with an IP will have the same
     * hashcode.
     */

    @Override
    public int hashCode () {
        return this.address;
    }


    /**
     * Determines if this address is equal two another. Only the IP Addresses
     * are compared. Similar to the {@link #hashCode} method, the comparison
     * is based on the integer IP address and not the string representation.
     */

    @Override
    public boolean equals ( Object obj ) {
        return ( obj != null ) && ( obj instanceof NbtAddress ) && ( ( (NbtAddress) obj ).address == this.address );
    }


    /**
     * Returns the {@link java.lang.String} representaion of this address.
     */

    @Override
    public String toString () {
        return this.hostName.toString() + "/" + getHostAddress();
    }
}
