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
package jcifs.smb;


import jcifs.CIFSContext;


/**
 * @author mbechler
 *
 */
public interface Dfs {

    /**
     * @param domain
     * @param tf
     * @return whether the given domain is trusted
     * @throws SmbAuthException
     */
    boolean isTrustedDomain ( CIFSContext tf, String domain ) throws SmbAuthException;


    /**
     * Get a connection to the domain controller for a given domain
     * 
     * @param domain
     * @param tf
     * @return connection
     * @throws SmbAuthException
     */
    SmbTransport getDc ( CIFSContext tf, String domain ) throws SmbAuthException;


    /**
     * Get a referral from a server
     * 
     * @param tf
     * @param trans
     * @param domain
     * @param root
     * @param path
     * @return a referral for the given DFS path
     * @throws SmbAuthException
     */
    DfsReferral getReferral ( CIFSContext tf, SmbTransport trans, String domain, String root, String path ) throws SmbAuthException;


    /**
     * Resolve the location of a DFS path
     * 
     * @param domain
     * @param root
     * @param path
     * @param tf
     * @return the final referral for the given DFS path
     * @throws SmbAuthException
     */
    DfsReferral resolve ( CIFSContext tf, String domain, String root, String path ) throws SmbAuthException;


    /**
     * Add a referral to the cache
     * 
     * @param path
     * @param dr
     * @param tc
     */
    void cache ( CIFSContext tc, String path, DfsReferral dr );

}