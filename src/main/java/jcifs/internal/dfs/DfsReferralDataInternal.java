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
package jcifs.internal.dfs;


import java.util.Map;

import jcifs.DfsReferralData;


/**
 * @author mbechler
 *
 */
public interface DfsReferralDataInternal extends DfsReferralData {

    /**
     * Replaces the host with the given FQDN if it is currently unqualified
     * 
     * @param fqdn
     */
    void fixupHost ( String fqdn );


    /**
     * Possibly appends the given domain name to the host name if it is currently unqualified
     * 
     * @param domain
     */
    void fixupDomain ( String domain );


    /**
     * Reduces path consumed by the given value
     * 
     * @param i
     */
    void stripPathConsumed ( int i );


    @Override
    DfsReferralDataInternal next ();


    /**
     * @param link
     */
    void setLink ( String link );


    /**
     * @return cache key
     */
    String getKey ();


    /**
     * 
     * @param key
     *            cache key
     */
    void setKey ( String key );


    /**
     * @param map
     */
    void setCacheMap ( Map<String, DfsReferralDataInternal> map );


    /**
     * Replaces the entry with key in the cache map with this referral
     */
    void replaceCache ();


    /**
     * Not exactly sure what that is all about, certainly legacy stuff
     * 
     * @return resolveHashes
     */
    boolean isResolveHashes ();


    /**
     * @return whether this refrral needs to be resolved further
     */
    boolean isIntermediate ();


    /**
     * @param next
     * @return new referral, combining a chain of referrals
     */
    DfsReferralDataInternal combine ( DfsReferralData next );


    /**
     * @param dr
     */
    void append ( DfsReferralDataInternal dr );
}
