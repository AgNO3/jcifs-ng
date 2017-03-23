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


import java.util.Locale;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.DfsReferralData;


/**
 * @author mbechler
 *
 */
class DfsReferralDataImpl implements DfsReferralDataInternal {

    private static final Logger log = LoggerFactory.getLogger(DfsReferralDataImpl.class);

    int pathConsumed;
    long ttl;
    String server; // Server
    String share; // Share
    String link;
    String path; // Path relative to tree from which this referral was thrown

    long expiration;
    int rflags;

    boolean resolveHashes;

    private DfsReferralDataImpl next;
    private Map<String, DfsReferralDataInternal> map;
    private String key = null;


    /**
     * 
     */
    public DfsReferralDataImpl () {
        this.next = this;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.DfsReferralData#unwrap(java.lang.Class)
     */
    @SuppressWarnings ( "unchecked" )
    @Override
    public <T extends DfsReferralData> T unwrap ( Class<T> type ) {
        if ( type.isAssignableFrom(this.getClass()) ) {
            return (T) this;
        }
        throw new ClassCastException();
    }


    @Override
    public long getExpiration () {
        return this.expiration;
    }


    @Override
    public int getPathConsumed () {
        return this.pathConsumed;
    }


    public String getLink () {
        return this.link;
    }


    @Override
    public void setLink ( String link ) {
        this.link = link;
    }


    /**
     * @return the key
     */
    @Override
    public String getKey () {
        return this.key;
    }


    /**
     * @param key
     *            the key to set
     */
    @Override
    public void setKey ( String key ) {
        this.key = key;
    }


    @Override
    public String getServer () {
        return this.server;
    }


    @Override
    public String getShare () {
        return this.share;
    }


    @Override
    public String getPath () {
        return this.path;
    }


    /**
     * @return the rflags
     */
    public int getFlags () {
        return this.rflags;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.DfsReferralDataInternal#setCacheMap(java.util.Map)
     */
    @Override
    public void setCacheMap ( Map<String, DfsReferralDataInternal> map ) {
        this.map = map;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.DfsReferralDataInternal#replaceCache()
     */
    @Override
    public void replaceCache () {
        if ( this.map != null && this.key != null ) {
            this.map.put(this.key, this);
        }
    }


    @Override
    public DfsReferralDataImpl next () {
        return this.next;
    }


    void append ( DfsReferralDataImpl dr ) {
        dr.next = this.next;
        this.next = dr;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.DfsReferralDataInternal#stripPathConsumed(int)
     */
    @Override
    public void stripPathConsumed ( int i ) {
        this.pathConsumed -= i;
    }


    @Override
    public void fixupDomain ( String domain ) {
        String s = getServer();
        if ( s.indexOf('.') < 0 && s.toUpperCase(Locale.ROOT).equals(s) ) {
            String fqdn = s + "." + domain;
            if ( log.isDebugEnabled() ) {
                log.debug(String.format("Applying DFS netbios name hack %s -> %s ", s, fqdn));
            }
            this.server = fqdn;
        }
    }


    @Override
    public void fixupHost ( String fqdn ) {
        String s = getServer();
        if ( s.indexOf('.') < 0 && s.toUpperCase(Locale.ROOT).equals(s) ) {
            if ( fqdn.startsWith(s.toLowerCase(Locale.ROOT) + ".") ) {
                if ( log.isDebugEnabled() ) {
                    log.debug("Adjusting server name " + s + " to " + fqdn);
                }
                this.server = fqdn;
            }
            else {
                log.warn("Have unmappable netbios name " + s);
            }
        }
    }


    /**
     * @return the resolveHashes
     */
    @Override
    public boolean isResolveHashes () {
        return this.resolveHashes;
    }


    @Override
    public String toString () {
        return "DfsReferralData[pathConsumed=" + this.pathConsumed + ",server=" + this.server + ",share=" + this.share + ",link=" + this.link
                + ",path=" + this.path + ",ttl=" + this.ttl + ",expiration=" + this.expiration + ",remain="
                + ( this.expiration - System.currentTimeMillis() ) + "]";
    }


    /**
     * @return the ttl
     */
    public long getTtl () {
        return this.ttl;
    }

}
