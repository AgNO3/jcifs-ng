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
package jcifs.smb;


import jcifs.Configuration;


/**
 * @author mbechler
 *
 */
public interface SmbTreeHandle extends AutoCloseable {

    /**
     * 
     * @throws SmbException
     */
    void ensureDFSResolved () throws SmbException;


    /**
     * @param cap
     * @return whether the capabiltiy is present
     * @throws SmbException
     */
    boolean hasCapability ( int cap ) throws SmbException;


    /**
     * @return the tree is connected
     */
    boolean isConnected ();


    /**
     * @return the active configuration
     */
    Configuration getConfig ();


    /**
     * {@inheritDoc}
     *
     * @see java.lang.AutoCloseable#close()
     */
    @Override
    void close () throws SmbException;


    /**
     * 
     */
    void release ();


    /**
     * @return server timezone offset
     */
    long getServerTimeZoneOffset ();


    /**
     * @return server reported domain name
     */
    String getOEMDomainName ();


    /**
     * @return the service we are connected to
     */
    String getConnectedService ();


    /**
     * @return the share we are connected to
     */
    String getConnectedShare ();


    /**
     * @param th
     * @return whether the handles refer to the same tree
     */
    boolean isSameTree ( SmbTreeHandleImpl th );


    /**
     * @return the send buffer size of the underlying connection
     */
    int getSendBufferSize ();


    /**
     * @return the receive buffer size of the underlying connection
     */
    int getReceiveBufferSize ();


    /**
     * @return the maximum buffer size reported by the server
     */
    int getMaximumBufferSize ();


    /**
     * @return whether the session uses SMB signing
     */
    boolean areSignaturesActive ();

}