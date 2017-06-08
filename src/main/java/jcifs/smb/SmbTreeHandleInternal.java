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


import jcifs.CIFSException;
import jcifs.SmbSession;
import jcifs.SmbTreeHandle;


/**
 * @author mbechler
 *
 */
public interface SmbTreeHandleInternal extends SmbTreeHandle {

    /**
     * 
     */
    void release ();


    /**
     * 
     * @throws SmbException
     * @throws CIFSException
     */
    void ensureDFSResolved () throws CIFSException;


    /**
     * @param cap
     * @return whether the capabiltiy is present
     * @throws CIFSException
     */
    boolean hasCapability ( int cap ) throws CIFSException;


    /**
     * @return the send buffer size of the underlying connection
     * @throws CIFSException
     */
    int getSendBufferSize () throws CIFSException;


    /**
     * @return the receive buffer size of the underlying connection
     * @throws CIFSException
     */
    int getReceiveBufferSize () throws CIFSException;


    /**
     * @return the maximum buffer size reported by the server
     * @throws CIFSException
     */
    int getMaximumBufferSize () throws CIFSException;


    /**
     * @return whether the session uses SMB signing
     * @throws CIFSException
     * @throws SmbException
     */
    boolean areSignaturesActive () throws CIFSException;


    /**
     * Internal/testing use only
     * 
     * @return attached session
     */
    SmbSession getSession ();
}
