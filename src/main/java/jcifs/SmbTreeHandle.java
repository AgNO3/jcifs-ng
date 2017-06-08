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


/**
 * Handle to a connected SMB tree
 * 
 * @author mbechler
 *
 */
public interface SmbTreeHandle extends AutoCloseable {

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
    void close () throws CIFSException;


    /**
     * @return the tree is connected
     */
    boolean isConnected ();


    /**
     * @return server timezone offset
     * @throws CIFSException
     */
    long getServerTimeZoneOffset () throws CIFSException;


    /**
     * @return server reported domain name
     * @throws CIFSException
     */
    String getOEMDomainName () throws CIFSException;


    /**
     * @return the share we are connected to
     */
    String getConnectedShare ();


    /**
     * @param th
     * @return whether the handles refer to the same tree
     */
    boolean isSameTree ( SmbTreeHandle th );


    /**
     * @return whether this tree handle uses SMB2+
     */
    boolean isSMB2 ();


    /**
     * @return the remote host name
     */
    String getRemoteHostName ();


    /**
     * @return the tree type
     */
    int getTreeType ();

}