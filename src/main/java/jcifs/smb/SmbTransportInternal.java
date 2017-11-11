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


import java.io.IOException;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.DfsReferralData;
import jcifs.SmbSession;
import jcifs.SmbTransport;


/**
 * @author mbechler
 *
 */
public interface SmbTransportInternal extends SmbTransport {

    /**
     * @param cap
     * @return whether the transport has the given capability
     * @throws SmbException
     */
    boolean hasCapability ( int cap ) throws SmbException;


    /**
     * @return whether the transport has been disconnected
     */
    boolean isDisconnected ();


    /**
     * @param hard
     * @param inuse
     * @return whether the connection was in use
     * @throws IOException
     */
    boolean disconnect ( boolean hard, boolean inuse ) throws IOException;


    /**
     * @return whether the transport was connected
     * @throws SmbException
     * @throws IOException
     * 
     */
    boolean ensureConnected () throws IOException;


    /**
     * @param ctx
     * @param name
     * @param targetHost
     * @param targetDomain
     * @param rn
     * @return dfs referral
     * @throws SmbException
     * @throws CIFSException
     */
    DfsReferralData getDfsReferrals ( CIFSContext ctx, String name, String targetHost, String targetDomain, int rn ) throws CIFSException;


    /**
     * @return whether signatures are supported but not required
     * @throws SmbException
     */
    boolean isSigningOptional () throws SmbException;


    /**
     * @return whether signatures are enforced from either side
     * @throws SmbException
     */
    boolean isSigningEnforced () throws SmbException;


    /**
     * @return the encryption key used by the server
     */
    byte[] getServerEncryptionKey ();


    /**
     * @param ctx
     * @return session
     */
    SmbSession getSmbSession ( CIFSContext ctx );


    /**
     * @param tf
     * @param targetHost
     * @param targetDomain
     * @return session
     */
    SmbSession getSmbSession ( CIFSContext tf, String targetHost, String targetDomain );


    /**
     * @return whether this is a SMB2 connection
     * @throws SmbException
     */
    boolean isSMB2 () throws SmbException;


    /**
     * @return number of inflight requests
     */
    int getInflightRequests ();
}
