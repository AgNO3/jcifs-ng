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

import jcifs.Address;
import jcifs.CIFSContext;
import jcifs.NetbiosAddress;
import jcifs.NetbiosName;


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

public final class NbtAddress implements NetbiosAddress {

    /**
     * This is a special name that means all hosts. If you wish to find all hosts
     * on a network querying a workgroup group name is the preferred method.
     */
    public static final String ANY_HOSTS_NAME = "*\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000";

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

    /**
     * Unknown MAC Address
     */
    public static final byte[] UNKNOWN_MAC_ADDRESS = new byte[] {
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
    };

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
     * {@inheritDoc}
     *
     * @see jcifs.Address#unwrap(java.lang.Class)
     */
    @SuppressWarnings ( "unchecked" )
    @Override
    public <T extends Address> T unwrap ( Class<T> type ) {
        if ( type.isAssignableFrom(this.getClass()) ) {
            return (T) this;
        }
        return null;
    }


    /**
     * Guess next called name to try for session establishment. These
     * methods are used by the smb package.
     * 
     * @return guessed name
     */
    @Override
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
    @Override
    public String nextCalledName ( CIFSContext tc ) {

        if ( this.calledName == this.hostName.name ) {
            this.calledName = SMBSERVER_NAME;
        }
        else if ( SMBSERVER_NAME.equals(this.calledName) ) {
            NetbiosAddress[] addrs;

            try {
                addrs = tc.getNameServiceClient().getNodeStatus(this);
                if ( this.getNameType() == 0x1D ) {
                    for ( int i = 0; i < addrs.length; i++ ) {
                        if ( addrs[ i ].getNameType() == 0x20 ) {
                            return addrs[ i ].getHostName();
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
                    return getHostName();
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
            tc.getNameServiceClient().getNbtAllByAddress(this);
        }
    }


    void checkNodeStatusData ( CIFSContext tc ) throws UnknownHostException {
        if ( this.isDataFromNodeStatus == false ) {
            tc.getNameServiceClient().getNbtAllByAddress(this);
        }
    }


    @Override
    public boolean isGroupAddress ( CIFSContext tc ) throws UnknownHostException {
        checkData(tc);
        return this.groupName;
    }


    @Override
    public int getNodeType ( CIFSContext tc ) throws UnknownHostException {
        checkData(tc);
        return this.nodeType;
    }


    @Override
    public boolean isBeingDeleted ( CIFSContext tc ) throws UnknownHostException {
        checkNodeStatusData(tc);
        return this.isBeingDeleted;
    }


    @Override
    public boolean isInConflict ( CIFSContext tc ) throws UnknownHostException {
        checkNodeStatusData(tc);
        return this.isInConflict;
    }


    @Override
    public boolean isActive ( CIFSContext tc ) throws UnknownHostException {
        checkNodeStatusData(tc);
        return this.isActive;
    }


    @Override
    public boolean isPermanent ( CIFSContext tc ) throws UnknownHostException {
        checkNodeStatusData(tc);
        return this.isPermanent;
    }


    @Override
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
    @Override
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


    @Override
    public NetbiosName getName () {
        return this.hostName;
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


    @Override
    public InetAddress toInetAddress () throws UnknownHostException {
        return getInetAddress();
    }


    /**
     * Returns this IP adress as a {@link java.lang.String} in the form "%d.%d.%d.%d".
     * 
     * @return string representation of the IP address
     */

    @Override
    public String getHostAddress () {
        return ( ( this.address >>> 24 ) & 0xFF ) + "." + ( ( this.address >>> 16 ) & 0xFF ) + "." + ( ( this.address >>> 8 ) & 0xFF ) + "."
                + ( ( this.address >>> 0 ) & 0xFF );
    }


    @Override
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
