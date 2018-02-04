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


import java.util.Locale;
import java.util.Map;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.DfsReferralData;
import jcifs.internal.smb1.trans2.Trans2GetDfsReferralResponse;


/**
 * @author mbechler
 *
 */
public class DfsReferralDataImpl implements DfsReferralDataInternal {

    private static final Logger log = LoggerFactory.getLogger(DfsReferralDataImpl.class);

    private int pathConsumed;
    private long ttl;
    private String server; // Server
    private String share; // Share
    private String link;
    private String path; // Path relative to tree from which this referral was thrown

    private long expiration;
    private int rflags;

    private boolean resolveHashes;

    private DfsReferralDataImpl next;
    private Map<String, DfsReferralDataInternal> map;
    private String key;
    private String domain;

    private boolean intermediate;


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


    /**
     * {@inheritDoc}
     *
     * @see jcifs.DfsReferralData#getDomain()
     */
    @Override
    public String getDomain () {
        return this.domain;
    }


    /**
     * @param domain
     *            the domain to set
     */
    public void setDomain ( String domain ) {
        this.domain = domain;
    }


    @Override
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
     * @see jcifs.internal.dfs.DfsReferralDataInternal#setCacheMap(java.util.Map)
     */
    @Override
    public void setCacheMap ( Map<String, DfsReferralDataInternal> map ) {
        this.map = map;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.dfs.DfsReferralDataInternal#replaceCache()
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


    /**
     * 
     * @param dr
     */
    @Override
    public void append ( DfsReferralDataInternal dr ) {
        DfsReferralDataImpl dri = (DfsReferralDataImpl) dr;
        dri.next = this.next;
        this.next = dri;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.dfs.DfsReferralDataInternal#stripPathConsumed(int)
     */
    @Override
    public void stripPathConsumed ( int i ) {
        if ( i > this.pathConsumed ) {
            throw new IllegalArgumentException("Stripping more than consumed");
        }
        this.pathConsumed -= i;
    }


    @Override
    public void fixupDomain ( String dom ) {
        String s = getServer();
        if ( s.indexOf('.') < 0 && s.toUpperCase(Locale.ROOT).equals(s) ) {
            String fqdn = s + "." + dom;
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


    /**
     * 
     */
    public void intermediate () {
        this.intermediate = true;
    }


    /**
     * @return the intermediate
     */
    @Override
    public boolean isIntermediate () {
        return this.intermediate;
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


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode () {
        return Objects.hash(this.server, this.share, this.path, this.pathConsumed);
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals ( Object obj ) {
        if ( ! ( obj instanceof DfsReferralData ) ) {
            return false;
        }
        DfsReferralData other = (DfsReferralData) obj;

        return Objects.equals(getServer(), other.getServer()) && Objects.equals(getShare(), other.getShare())
                && Objects.equals(getPath(), other.getPath()) && Objects.equals(getPathConsumed(), other.getPathConsumed());
    }


    /**
     * @param ref
     * @param reqPath
     * @param expire
     * @param consumed
     * @return referral data
     */
    public static DfsReferralDataImpl fromReferral ( Referral ref, String reqPath, long expire, int consumed ) {
        DfsReferralDataImpl dr = new DfsReferralDataImpl();
        String[] arr = new String[4];
        dr.ttl = ref.getTtl();
        dr.rflags = ref.getRFlags();
        dr.expiration = expire;
        if ( ( dr.rflags & Trans2GetDfsReferralResponse.FLAGS_NAME_LIST_REFERRAL ) == Trans2GetDfsReferralResponse.FLAGS_NAME_LIST_REFERRAL ) {
            String[] expandedNames = ref.getExpandedNames();
            if ( expandedNames.length > 0 ) {
                dr.server = expandedNames[ 0 ].substring(1).toLowerCase();
            }
            else {
                dr.server = ref.getSpecialName().substring(1).toLowerCase();
            }
            if ( log.isDebugEnabled() ) {
                log.debug("Server " + dr.server + " path " + reqPath + " remain " + reqPath.substring(consumed) + " path consumed " + consumed);
            }
            dr.pathConsumed = consumed;
        }
        else {
            if ( log.isDebugEnabled() ) {
                log.debug("Node " + ref.getNode() + " path " + reqPath + " remain " + reqPath.substring(consumed) + " path consumed " + consumed);
            }
            dfsPathSplit(ref.getNode(), arr);
            dr.server = arr[ 1 ];
            dr.share = arr[ 2 ];
            dr.path = arr[ 3 ];
            dr.pathConsumed = consumed;

            /*
             * Samba has a tendency to return pathConsumed values so that they consume a trailing slash of the
             * requested path. Normalize this here.
             */
            if ( reqPath.charAt(consumed - 1) == '\\' ) {
                if ( log.isDebugEnabled() ) {
                    log.debug("Server consumed trailing slash of request path, adjusting");
                }
                dr.pathConsumed--;
            }

            if ( log.isDebugEnabled() ) {
                String cons = reqPath.substring(0, consumed);
                log.debug("Request " + reqPath + " ref path " + dr.path + " consumed " + dr.pathConsumed + ": " + cons);
            }
        }

        return dr;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.dfs.DfsReferralDataInternal#combine(jcifs.DfsReferralData)
     */
    @Override
    public DfsReferralDataInternal combine ( DfsReferralData n ) {
        DfsReferralDataImpl dr = new DfsReferralDataImpl();
        dr.server = n.getServer();
        dr.share = n.getShare();
        dr.expiration = n.getExpiration();
        dr.path = n.getPath();
        dr.pathConsumed = this.pathConsumed + n.getPathConsumed();
        if ( this.path != null ) {
            dr.pathConsumed -= ( this.path != null ? this.path.length() + 1 : 0 );
        }
        dr.domain = n.getDomain();
        return dr;
    }


    /*
     * Split DFS path like \fs1.example.com\root5\link2\foo\bar.txt into at
     * most 3 components (not including the first index which is always empty):
     * result[0] = ""
     * result[1] = "fs1.example.com"
     * result[2] = "root5"
     * result[3] = "link2\foo\bar.txt"
     */
    private static int dfsPathSplit ( String path, String[] result ) {
        int ri = 0, rlast = result.length - 1;
        int i = 0, b = 0, len = path.length();
        int strip = 0;

        do {
            if ( ri == rlast ) {
                result[ rlast ] = path.substring(b);
                return strip;
            }
            if ( i == len || path.charAt(i) == '\\' ) {
                result[ ri++ ] = path.substring(b, i);
                strip++;
                b = i + 1;
            }
        }
        while ( i++ < len );

        while ( ri < result.length ) {
            result[ ri++ ] = "";
        }

        return strip;
    }

}
