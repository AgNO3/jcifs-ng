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
package jcifs;


import java.net.InetAddress;
import java.net.UnknownHostException;


/**
 * 
 * This is an internal API for resolving names
 * 
 * @author mbechler
 * @internal
 */
public interface NameServiceClient {

    /**
     * @return local host address
     */
    NetbiosAddress getLocalHost ();


    /**
     * @return the local host name
     */
    NetbiosName getLocalName ();


    /**
     * @return the unknown name
     */
    NetbiosName getUnknownName ();


    /**
     * Retrieve all addresses of a host by it's address. NetBIOS hosts can
     * have many names for a given IP address. The name and IP address make the
     * NetBIOS address. This provides a way to retrieve the other names for a
     * host with the same IP address.
     *
     * @param addr
     *            the address to query
     * @return resolved addresses
     * @throws UnknownHostException
     *             if address cannot be resolved
     */
    NetbiosAddress[] getNbtAllByAddress ( NetbiosAddress addr ) throws UnknownHostException;


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
     * @return resolved addresses
     * @throws java.net.UnknownHostException
     *             if there is an error resolving the name
     */
    NetbiosAddress[] getNbtAllByAddress ( String host, int type, String scope ) throws UnknownHostException;


    /**
     * Retrieve all addresses of a host by it's address. NetBIOS hosts can
     * have many names for a given IP address. The name and IP address make the
     * NetBIOS address. This provides a way to retrieve the other names for a
     * host with the same IP address.
     *
     * @param host
     *            hostname to lookup all addresses for
     * @return resolved addresses
     * @throws java.net.UnknownHostException
     *             if there is an error resolving the name
     */
    NetbiosAddress[] getNbtAllByAddress ( String host ) throws UnknownHostException;


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
     * 
     * @return the resolved addresses
     * @throws UnknownHostException
     */
    NetbiosAddress[] getNbtAllByName ( String host, int type, String scope, InetAddress svr ) throws UnknownHostException;


    /**
     * Determines the address of a host given it's host name. NetBIOS
     * names also have a <code>type</code>. Types(aka Hex Codes)
     * are used to distinguish the various services on a host. <a
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
     * @return the resolved address
     * @throws java.net.UnknownHostException
     *             if there is an error resolving the name
     */
    NetbiosAddress getNbtByName ( String host, int type, String scope, InetAddress svr ) throws UnknownHostException;


    /**
     * Determines the address of a host given it's host name. NetBIOS
     * names also have a <code>type</code>. Types(aka Hex Codes)
     * are used to distinguish the various services on a host. <a
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
     * @return the resolved address
     * @throws java.net.UnknownHostException
     *             if there is an error resolving the name
     */
    NetbiosAddress getNbtByName ( String host, int type, String scope ) throws UnknownHostException;


    /**
     * Determines the address of a host given it's host name. The name can be a NetBIOS name like
     * "freto" or an IP address like "192.168.1.15". It cannot be a DNS name;
     * the analygous {@link jcifs.netbios.UniAddress} or {@link java.net.InetAddress}
     * <code>getByName</code> methods can be used for that.
     *
     * @param host
     *            hostname to resolve
     * @return the resolved address
     * @throws java.net.UnknownHostException
     *             if there is an error resolving the name
     */
    NetbiosAddress getNbtByName ( String host ) throws UnknownHostException;


    /**
     * @param nbtAddress
     * @return the node status responses
     * @throws UnknownHostException
     */
    NetbiosAddress[] getNodeStatus ( NetbiosAddress nbtAddress ) throws UnknownHostException;


    /**
     * Lookup addresses for the given <tt>hostname</tt>.
     * 
     * @param hostname
     * @param possibleNTDomainOrWorkgroup
     * @return found addresses
     * @throws UnknownHostException
     */
    Address[] getAllByName ( String hostname, boolean possibleNTDomainOrWorkgroup ) throws UnknownHostException;


    /**
     * Lookup <tt>hostname</tt> and return it's <tt>UniAddress</tt>. If the
     * <tt>possibleNTDomainOrWorkgroup</tt> parameter is <tt>true</tt> an
     * additional name query will be performed to locate a master browser.
     * 
     * @param hostname
     * @param possibleNTDomainOrWorkgroup
     * 
     * @return the first resolved address
     * @throws UnknownHostException
     */
    Address getByName ( String hostname, boolean possibleNTDomainOrWorkgroup ) throws UnknownHostException;


    /**
     * Determines the address of a host given it's host name. The name can be a
     * machine name like "jcifs.samba.org", or an IP address like "192.168.1.15".
     *
     * @param hostname
     *            NetBIOS or DNS hostname to resolve
     * @return the found address
     * @throws java.net.UnknownHostException
     *             if there is an error resolving the name
     */
    Address getByName ( String hostname ) throws UnknownHostException;

}