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


import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;


/**
 * This is an internal API for managing pools of SMB connections
 * 
 * @author mbechler
 * @internal
 */
public interface SmbTransportPool {

    /**
     * @param tf
     * @param name
     * @param port
     * @param exclusive
     * @param forceSigning
     * @return a connected transport
     * @throws UnknownHostException
     * @throws IOException
     */
    SmbTransport getSmbTransport ( CIFSContext tf, String name, int port, boolean exclusive, boolean forceSigning )
            throws UnknownHostException, IOException;


    /**
     * Get transport connection
     * 
     * @param tc
     *            context to use
     * @param address
     * @param port
     * @param exclusive
     *            whether to acquire an unshared connection
     * @return a transport connection to the target
     */
    SmbTransport getSmbTransport ( CIFSContext tc, Address address, int port, boolean exclusive );


    /**
     * Get transport connection
     * 
     * @param tc
     *            context to use
     * @param address
     * @param port
     * @param exclusive
     *            whether to acquire an unshared connection
     * @param forceSigning
     *            whether to enforce SMB signing on this connection
     * @return a transport connection to the target
     */
    SmbTransport getSmbTransport ( CIFSContext tc, Address address, int port, boolean exclusive, boolean forceSigning );


    /**
     * Get transport connection, with local binding
     * 
     * @param tc
     *            context to use
     * @param address
     * @param port
     * @param localAddr
     * @param localPort
     * @param hostName
     * @param exclusive
     *            whether to acquire an unshared connection
     * @return a transport connection to the target
     */
    SmbTransport getSmbTransport ( CIFSContext tc, Address address, int port, InetAddress localAddr, int localPort, String hostName,
            boolean exclusive );


    /**
     * @param tc
     *            context to use
     * @param address
     * @param port
     * @param localAddr
     * @param localPort
     * @param hostName
     * @param exclusive
     *            whether to acquire an unshared connection
     * @param forceSigning
     *            whether to enforce SMB signing on this connection
     * @return a transport connection to the target
     */
    SmbTransport getSmbTransport ( CIFSContext tc, Address address, int port, InetAddress localAddr, int localPort, String hostName,
            boolean exclusive, boolean forceSigning );


    /**
     * 
     * @param trans
     */
    void removeTransport ( SmbTransport trans );


    /**
     * Closes the pool and all connections in it
     * 
     * @return whether any transport was still in use
     * 
     * @throws CIFSException
     * 
     */
    boolean close () throws CIFSException;


    /**
     * Authenticate arbitrary credentials represented by the
     * <tt>NtlmPasswordAuthentication</tt> object against the domain controller
     * specified by the <tt>UniAddress</tt> parameter. If the credentials are
     * not accepted, an <tt>SmbAuthException</tt> will be thrown. If an error
     * occurs an <tt>SmbException</tt> will be thrown. If the credentials are
     * valid, the method will return without throwing an exception. See the
     * last <a href="../../../faq.html">FAQ</a> question.
     * <p>
     * See also the <tt>jcifs.smb.client.logonShare</tt> property.
     * 
     * @param dc
     * @param tc
     * @throws CIFSException
     */
    void logon ( CIFSContext tc, Address dc ) throws CIFSException;


    /**
     * Authenticate arbitrary credentials represented by the
     * <tt>NtlmPasswordAuthentication</tt> object against the domain controller
     * specified by the <tt>UniAddress</tt> parameter. If the credentials are
     * not accepted, an <tt>SmbAuthException</tt> will be thrown. If an error
     * occurs an <tt>SmbException</tt> will be thrown. If the credentials are
     * valid, the method will return without throwing an exception. See the
     * last <a href="../../../faq.html">FAQ</a> question.
     * <p>
     * See also the <tt>jcifs.smb.client.logonShare</tt> property.
     * 
     * @param dc
     * @param port
     * @param tc
     * @throws CIFSException
     */
    void logon ( CIFSContext tc, Address dc, int port ) throws CIFSException;


    /**
     * Get NTLM challenge from a server
     * 
     * @param dc
     * @param tc
     * @return NTLM challenge
     * @throws CIFSException
     */
    byte[] getChallenge ( CIFSContext tc, Address dc ) throws CIFSException;


    /**
     * Get NTLM challenge from a server
     * 
     * @param dc
     * @param port
     * @param tc
     * @return NTLM challenge
     * @throws CIFSException
     */
    byte[] getChallenge ( CIFSContext tc, Address dc, int port ) throws CIFSException;

}