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


/**
 * This is an internal API.
 * 
 * @author mbechler
 * @internal
 */
public interface DfsResolver {

    /**
     * @param domain
     * @param tf
     * @return whether the given domain is trusted
     * @throws CIFSException
     * @throws jcifs.smb.SmbAuthException
     */
    boolean isTrustedDomain ( CIFSContext tf, String domain ) throws CIFSException;


    /**
     * Get a connection to the domain controller for a given domain
     * 
     * @param domain
     * @param tf
     * @return connection
     * @throws CIFSException
     * @throws jcifs.smb.SmbAuthException
     */
    SmbTransport getDc ( CIFSContext tf, String domain ) throws CIFSException;


    /**
     * Resolve the location of a DFS path
     * 
     * @param domain
     * @param root
     * @param path
     * @param tf
     * @return the final referral for the given DFS path
     * @throws CIFSException
     * @throws jcifs.smb.SmbAuthException
     */
    DfsReferralData resolve ( CIFSContext tf, String domain, String root, String path ) throws CIFSException;


    /**
     * Add a referral to the cache
     * 
     * @param path
     * @param dr
     * @param tc
     */
    void cache ( CIFSContext tc, String path, DfsReferralData dr );

}