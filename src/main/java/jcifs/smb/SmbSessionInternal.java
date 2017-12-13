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
import jcifs.SmbTransport;
import jcifs.SmbTree;


/**
 * @author mbechler
 * @internal
 */
public interface SmbSessionInternal extends SmbSession {

    /**
     * @return whether the session is in use
     */
    boolean isInUse ();


    /**
     * @return the current session key
     * @throws CIFSException
     */
    byte[] getSessionKey () throws CIFSException;


    /**
     * 
     * @return the transport for this session
     */
    SmbTransport getTransport ();


    /**
     * Connect to the logon share
     * 
     * @throws SmbException
     */
    void treeConnectLogon () throws SmbException;


    /**
     * @param share
     * @param service
     * @return tree instance
     */
    SmbTree getSmbTree ( String share, String service );


    /**
     * Initiate reauthentication
     * 
     * @throws CIFSException
     */
    void reauthenticate () throws CIFSException;
}
