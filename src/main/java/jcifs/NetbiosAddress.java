/*
 * © 2017 AgNO3 Gmbh & Co. KG
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
package jcifs;


import java.net.UnknownHostException;


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
public interface NetbiosAddress extends Address {

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
    boolean isGroupAddress ( CIFSContext tc ) throws UnknownHostException;


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
    int getNodeType ( CIFSContext tc ) throws UnknownHostException;


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
    boolean isBeingDeleted ( CIFSContext tc ) throws UnknownHostException;


    /**
     * Determines if this address in conflict with another address.
     *
     * @param tc
     *            context to use
     * @return whether this address is in conflict with another address
     * @throws UnknownHostException
     *             if the host cannot be resolved to find out.
     */
    boolean isInConflict ( CIFSContext tc ) throws UnknownHostException;


    /**
     * Determines if this address is active.
     * 
     * @param tc
     *            context to use
     * @return whether this address is active
     *
     * @throws UnknownHostException
     *             if the host cannot be resolved to find out.
     */
    boolean isActive ( CIFSContext tc ) throws UnknownHostException;


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
    boolean isPermanent ( CIFSContext tc ) throws UnknownHostException;


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
    byte[] getMacAddress ( CIFSContext tc ) throws UnknownHostException;


    /**
     * Returned the hex code associated with this name(e.g. 0x20 is for the file service)
     * 
     * @return the name type
     */
    int getNameType ();


    /**
     * @return the name for this address
     */
    NetbiosName getName ();

}
