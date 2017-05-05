/* jcifs smb client library in Java
 * Copyright (C) 2008  "Michael B. Allen" <jcifs at samba dot org>
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
import java.util.HashMap;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.Address;
import jcifs.CIFSContext;
import jcifs.DfsReferralData;
import jcifs.DfsResolver;
import jcifs.SmbTransport;


/**
 * Caching DFS resolver implementation
 * 
 * @internal
 */
public class DfsImpl implements DfsResolver {

    private static class CacheEntry <T> {

        long expiration;
        Map<String, T> map;


        CacheEntry ( long ttl ) {
            this.expiration = System.currentTimeMillis() + ttl * 1000L;
            this.map = new HashMap<>();
        }
    }

    private static class NegativeCacheEntry <T> extends CacheEntry<T> {

        /**
         * @param ttl
         */
        NegativeCacheEntry ( long ttl ) {
            super(ttl);
        }

    }

    private static final Logger log = LoggerFactory.getLogger(DfsImpl.class);
    private static final String DC_ENTRY = "dc";

    private CacheEntry<Map<String, CacheEntry<DfsReferralDataInternal>>> _domains = null; /*
                                                                                           * aka trusted domains cache
                                                                                           */
    private final Object domainsLock = new Object();

    private Map<String, CacheEntry<DfsReferralDataInternal>> _dcs = new HashMap<>();
    private final Object dcLock = new Object();

    private CacheEntry<DfsReferralDataInternal> referrals = null;
    private final Object referralsLock = new Object();


    /**
     * @param tc
     * 
     */
    public DfsImpl ( CIFSContext tc ) {}


    private Map<String, Map<String, CacheEntry<DfsReferralDataInternal>>> getTrustedDomains ( CIFSContext tf ) throws SmbAuthException {
        if ( tf.getConfig().isDfsDisabled() || tf.getCredentials().getUserDomain() == null || tf.getCredentials().getUserDomain().isEmpty() ) {
            return null;
        }

        if ( this._domains != null && System.currentTimeMillis() > this._domains.expiration ) {
            this._domains = null;
        }
        if ( this._domains != null )
            return this._domains.map;
        try {
            String authDomain = tf.getCredentials().getUserDomain();
            // otherwise you end up with a wrong server name for kerberos
            // seems to be correct according to
            // https://lists.samba.org/archive/samba-technical/2009-August/066486.html
            // UniAddress addr = UniAddress.getByName(authDomain, true, tf);
            // SmbTransport trans = tf.getTransportPool().getSmbTransport(tf, addr, 0);
            try ( SmbTransport dc = getDc(tf, authDomain) ) {
                CacheEntry<Map<String, CacheEntry<DfsReferralDataInternal>>> entry = new CacheEntry<>(tf.getConfig().getDfsTtl() * 10L);
                DfsReferralData initial = null;
                @SuppressWarnings ( "resource" )
                SmbTransportInternal trans = dc != null ? dc.unwrap(SmbTransportInternal.class) : null;
                if ( trans != null ) {
                    // get domain referral
                    initial = trans.getDfsReferrals(tf, "", 0);
                }
                if ( initial != null ) {
                    DfsReferralDataInternal start = initial.unwrap(DfsReferralDataInternal.class);
                    DfsReferralDataInternal dr = start;
                    do {
                        String domain = dr.getServer().toLowerCase();
                        entry.map.put(domain, new HashMap<String, CacheEntry<DfsReferralDataInternal>>());
                        if ( log.isTraceEnabled() ) {
                            log.trace("Inserting cache entry for domain " + domain + ": " + dr);
                        }
                        dr = dr.next();
                    }
                    while ( dr != start );
                    this._domains = entry;
                    return this._domains.map;
                }
            }
        }
        catch ( IOException ioe ) {
            if ( log.isDebugEnabled() ) {
                log.debug("getting trusted domains failed: " + tf.getCredentials().getUserDomain(), ioe);
            }
            CacheEntry<Map<String, CacheEntry<DfsReferralDataInternal>>> entry = new CacheEntry<>(tf.getConfig().getDfsTtl() * 10L);
            this._domains = entry;
            if ( tf.getConfig().isDfsStrictView() && ioe instanceof SmbAuthException ) {
                throw (SmbAuthException) ioe;
            }
            return this._domains.map;
        }
        return null;
    }


    /**
     * 
     * {@inheritDoc}
     *
     * @see jcifs.DfsResolver#isTrustedDomain(jcifs.CIFSContext, java.lang.String)
     */
    @Override
    public boolean isTrustedDomain ( CIFSContext tf, String domain ) throws SmbAuthException {
        synchronized ( this.domainsLock ) {
            Map<String, Map<String, CacheEntry<DfsReferralDataInternal>>> domains = getTrustedDomains(tf);
            if ( domains == null )
                return false;
            domain = domain.toLowerCase();
            return domains.get(domain) != null;
        }
    }


    private DfsReferralData getDcReferrals ( CIFSContext tf, String domain ) throws SmbAuthException {
        if ( tf.getConfig().isDfsDisabled() )
            return null;
        String dom = domain.toLowerCase(Locale.ROOT);
        synchronized ( this.dcLock ) {
            CacheEntry<DfsReferralDataInternal> ce = this._dcs.get(dom);
            if ( ce != null && System.currentTimeMillis() > ce.expiration ) {
                ce = null;
            }
            if ( ce != null ) {
                return ce.map.get(DC_ENTRY);
            }
            ce = new CacheEntry<>(tf.getConfig().getDfsTtl());
            try {
                IOException se = null;
                Address[] addrs = tf.getNameServiceClient().getAllByName(domain, true);
                for ( Address addr : addrs ) {
                    try ( SmbTransportInternal trans = tf.getTransportPool().getSmbTransport(tf, addr, 0, false)
                            .unwrap(SmbTransportInternal.class) ) {
                        synchronized ( trans ) {
                            DfsReferralDataInternal dr = trans.getDfsReferrals(tf.withAnonymousCredentials(), "\\" + domain, 1)
                                    .unwrap(DfsReferralDataInternal.class);
                            if ( log.isDebugEnabled() ) {
                                log.debug("Got DC referral " + dr);
                            }
                            ce.map.put(DC_ENTRY, dr);
                            return dr;
                        }
                    }
                    catch ( IOException e ) {
                        log.debug("Failed to get DC referral for " + domain, e);
                        se = e;
                        continue;
                    }
                }
                if ( se != null ) {
                    throw se;
                }
            }
            catch ( IOException ioe ) {
                if ( log.isDebugEnabled() ) {
                    log.debug(String.format("Getting domain controller for %s failed", domain), ioe);
                }
                ce.map.put(DC_ENTRY, null);
                if ( tf.getConfig().isDfsStrictView() && ioe instanceof SmbAuthException ) {
                    throw (SmbAuthException) ioe;
                }
            }
            ce.map.put(DC_ENTRY, null);
            this._dcs.put(dom, ce);
            return null;
        }
    }


    /**
     * 
     * {@inheritDoc}
     *
     * @see jcifs.DfsResolver#getDc(jcifs.CIFSContext, java.lang.String)
     */
    @Override
    public SmbTransport getDc ( CIFSContext tf, String domain ) throws SmbAuthException {
        if ( tf.getConfig().isDfsDisabled() )
            return null;
        try {
            DfsReferralData dr = getDcReferrals(tf, domain);
            if ( dr != null ) {
                DfsReferralData start = dr;
                IOException e = null;
                do {
                    try {
                        if ( dr.getServer() != null && !dr.getServer().isEmpty() ) {
                            return tf.getTransportPool().getSmbTransport(
                                tf,
                                tf.getNameServiceClient().getByName(dr.getServer()),
                                0,
                                false,
                                !tf.getCredentials().isAnonymous() && tf.getConfig().isIpcSigningEnforced());
                        }
                        log.debug("No server name in referral");
                        return null;
                    }
                    catch ( IOException ioe ) {
                        e = ioe;
                    }

                    dr = dr.next();
                }
                while ( dr != start );

                throw e;
            }
        }
        catch ( IOException ioe ) {
            if ( log.isDebugEnabled() ) {
                log.debug(String.format("Failed to connect to domain controller for %s", domain), ioe);
            }
            if ( tf.getConfig().isDfsStrictView() && ioe instanceof SmbAuthException ) {
                throw (SmbAuthException) ioe;
            }
        }
        return null;
    }


    protected DfsReferralDataInternal getReferral ( CIFSContext tf, SmbTransportInternal trans, String domain, String root, String path )
            throws SmbAuthException {
        if ( tf.getConfig().isDfsDisabled() )
            return null;

        String p = "\\" + domain + "\\" + root;
        if ( path != null )
            p += path;
        try {
            if ( log.isDebugEnabled() ) {
                log.debug("Fetching referral for " + p);
            }
            DfsReferralData dr = trans.getDfsReferrals(tf, p, 0);
            if ( dr != null ) {
                return dr.unwrap(DfsReferralDataInternal.class);
            }
        }
        catch ( IOException ioe ) {
            if ( log.isDebugEnabled() ) {
                log.debug(String.format("Getting referral for %s failed", p), ioe);
            }
            if ( tf.getConfig().isDfsStrictView() && ioe instanceof SmbAuthException ) {
                throw (SmbAuthException) ioe;
            }
        }
        return null;
    }


    /**
     * 
     * {@inheritDoc}
     *
     * @see jcifs.DfsResolver#resolve(jcifs.CIFSContext, java.lang.String, java.lang.String, java.lang.String)
     */
    @Override
    public DfsReferralData resolve ( CIFSContext tf, String domain, String root, String path ) throws SmbAuthException {

        if ( tf.getConfig().isDfsDisabled() || root == null || root.equals("IPC$") ) {
            return null;
        }

        if ( domain == null ) {
            return null;
        }

        if ( log.isTraceEnabled() ) {
            log.trace(String.format("Resolving \\%s\\%s%s", domain, root, path != null ? path : ""));
        }

        DfsReferralDataInternal dr = null;
        long now = System.currentTimeMillis();
        synchronized ( this.domainsLock ) {
            /*
             * domains that can contain DFS points to maps of roots for each
             */
            Map<String, Map<String, CacheEntry<DfsReferralDataInternal>>> domains = getTrustedDomains(tf);

            if ( domains != null ) {

                if ( log.isTraceEnabled() ) {
                    for ( Entry<String, Map<String, CacheEntry<DfsReferralDataInternal>>> entry : domains.entrySet() ) {
                        log.trace("Domain " + entry.getKey());
                        for ( Entry<String, CacheEntry<DfsReferralDataInternal>> entry2 : entry.getValue().entrySet() ) {
                            log.trace("  Root " + entry2.getKey());
                            if ( entry2.getValue().map != null ) {
                                for ( Entry<String, DfsReferralDataInternal> entry3 : entry2.getValue().map.entrySet() ) {
                                    DfsReferralDataInternal start = entry3.getValue();
                                    DfsReferralDataInternal r = start;
                                    do {
                                        log.trace("    " + entry3.getKey() + " => " + entry3.getValue());
                                        r = start.next();
                                    }
                                    while ( r != start );
                                }
                            }
                        }
                    }
                }
                domain = domain.toLowerCase();
                /*
                 * domain-based DFS root shares to links for each
                 */
                Map<String, CacheEntry<DfsReferralDataInternal>> roots = domains.get(domain);
                if ( roots != null ) {
                    if ( log.isTraceEnabled() ) {
                        log.trace("Is a domain referral for " + domain);
                    }

                    root = root.toLowerCase();

                    if ( log.isTraceEnabled() ) {
                        log.trace("Resolving root " + root);
                    }
                    /*
                     * The link entries contain maps of referrals by path representing DFS links.
                     * Note that paths are relative to the root like "\" and not "\example.com\root".
                     */
                    CacheEntry<DfsReferralDataInternal> links = roots.get(root);
                    if ( links != null && now > links.expiration ) {
                        if ( log.isDebugEnabled() ) {
                            log.debug("Removing expired " + links.map);
                        }
                        roots.remove(root);
                        links = null;
                    }

                    if ( links == null ) {
                        log.trace("Loadings links");
                        String refServerName = domain;
                        try ( SmbTransport dc = getDc(tf, domain) ) {
                            if ( dc == null ) {
                                if ( log.isDebugEnabled() ) {
                                    log.debug("Failed to get domain controller for " + domain);
                                }
                                return null;
                            }

                            @SuppressWarnings ( "resource" )
                            SmbTransportInternal trans = dc.unwrap(SmbTransportInternal.class);
                            // the tconHostName is from the DC referral, that referral must be resolved
                            // before following deeper ones. Otherwise e.g. samba will return a broken
                            // referral.
                            synchronized ( trans ) {
                                try {
                                    // ensure connected
                                    trans.ensureConnected();
                                    refServerName = trans.getRemoteHostName();
                                }
                                catch ( SmbException e ) {
                                    log.warn("Failed to connect to domain controller", e);
                                }
                                dr = getReferral(tf, trans, refServerName, root, path);
                            }
                        }

                        if ( log.isTraceEnabled() ) {
                            log.trace("Have referral " + dr);
                        }

                        if ( path == null && domain.equals(dr.getServer()) && root.equals(dr.getShare()) ) {
                            // If we do cache these we never get to the properly cached
                            // standalone referral we might have.
                            log.warn("Dropping self-referential referral " + dr);
                            dr = null;
                        }

                        if ( dr != null ) {
                            int len = 1 + refServerName.length() + 1 + root.length();

                            links = new CacheEntry<>(tf.getConfig().getDfsTtl());

                            DfsReferralDataInternal tmp = dr;
                            do {
                                if ( path == null ) {

                                    if ( log.isTraceEnabled() ) {
                                        log.trace("Path is empty, insert root " + tmp);
                                    }
                                    /*
                                     * Store references to the map and key so that
                                     * SmbFile.resolveDfs can re-insert the dr list with
                                     * the dr that was successful so that subsequent
                                     * attempts to resolve DFS use the last successful
                                     * referral first.
                                     */
                                    tmp.setCacheMap(links.map);
                                    tmp.setKey("\\");
                                }
                                tmp.stripPathConsumed(len);
                                tmp = tmp.next();
                            }
                            while ( tmp != dr );

                            if ( log.isDebugEnabled() ) {
                                log.debug("Have referral " + dr);
                            }

                            if ( dr.getKey() != null )
                                links.map.put(dr.getKey(), dr);

                            roots.put(root, links);
                        }
                        else if ( path == null ) {
                            roots.put(root, new NegativeCacheEntry<DfsReferralDataInternal>(tf.getConfig().getDfsTtl()));
                        }
                    }
                    else if ( links instanceof NegativeCacheEntry ) {
                        links = null;
                    }

                    if ( links != null ) {
                        String link = "\\";

                        /*
                         * Lookup the domain based DFS root target referral. Note the
                         * path is just "\" and not "\example.com\root".
                         */
                        dr = links.map.get(link);
                        if ( dr != null && now > dr.getExpiration() ) {
                            if ( log.isTraceEnabled() ) {
                                log.trace("Expiring links " + link);
                            }
                            links.map.remove(link);
                            dr = null;
                        }

                        if ( dr == null ) {
                            try ( SmbTransportInternal trans = getDc(tf, domain).unwrap(SmbTransportInternal.class) ) {
                                if ( trans == null )
                                    return null;

                                dr = getReferral(tf, trans, domain, root, path);
                                if ( dr != null ) {

                                    dr.stripPathConsumed(1 + domain.length() + 1 + root.length());
                                    dr.setLink(link);
                                    if ( log.isTraceEnabled() ) {
                                        log.trace("Have referral " + dr);
                                    }
                                    links.map.put(link, dr);
                                }
                                else {
                                    log.debug("No referral found for " + link);
                                }
                            }
                        }
                        else if ( log.isTraceEnabled() ) {
                            log.trace("Have cached referral " + dr);
                        }
                    }
                }

                if ( tf.getConfig().isDfsConvertToFQDN() && dr instanceof DfsReferralDataImpl ) {
                    ( (DfsReferralDataImpl) dr ).fixupDomain(domain);
                }
            }
        }

        if ( dr == null && path != null ) {
            if ( log.isTraceEnabled() ) {
                log.trace("No match for domain based root, checking standalone " + domain);
            }
            /*
             * We did not match a domain based root. Now try to match the
             * longest path in the list of stand-alone referrals.
             */
            if ( this.referrals != null && now > this.referrals.expiration ) {
                this.referrals = null;
            }
            if ( this.referrals == null ) {
                this.referrals = new CacheEntry<>(0);
            }
            String key = "\\" + domain + "\\" + root;
            if ( !path.equals("\\") )
                key += path;
            key = key.toLowerCase();

            Iterator<String> iter = this.referrals.map.keySet().iterator();
            while ( iter.hasNext() ) {
                String _key = iter.next();
                int _klen = _key.length();
                boolean match = false;

                if ( _klen == key.length() ) {
                    match = _key.equals(key);
                }
                else if ( _klen < key.length() ) {
                    match = _key.regionMatches(0, key, 0, _klen) && key.charAt(_klen) == '\\';
                }

                if ( match )
                    dr = this.referrals.map.get(_key);
            }
        }

        return dr;
    }


    @Override
    public synchronized void cache ( CIFSContext tc, String path, DfsReferralData dr ) {

        if ( tc.getConfig().isDfsDisabled() || ! ( dr instanceof DfsReferralDataInternal ) ) {
            return;
        }

        if ( log.isDebugEnabled() ) {
            log.debug("Inserting referral for " + path);
        }

        int s1 = path.indexOf('\\', 1);
        int s2 = path.indexOf('\\', s1 + 1);
        String server = path.substring(1, s1).toLowerCase(Locale.ROOT);
        String share = path.substring(s1 + 1, s2);
        String key = path.substring(0, dr.getPathConsumed()).toLowerCase(Locale.ROOT);

        DfsReferralDataInternal dri = (DfsReferralDataInternal) dr;

        /*
         * Samba has a tendency to return referral paths and pathConsumed values
         * in such a way that there can be a slash at the end of the path. This
         * causes problems matching keys in resolve() where an extra slash causes
         * a mismatch. This strips trailing slashes from all keys to eliminate
         * this problem.
         */
        int ki = key.length();
        while ( ki > 1 && key.charAt(ki - 1) == '\\' ) {
            ki--;
        }
        if ( ki < key.length() ) {
            key = key.substring(0, ki);
        }

        if ( tc.getConfig().isDfsConvertToFQDN() ) {
            dri.fixupHost(server);
        }

        if ( log.isDebugEnabled() ) {
            log.debug("Adding key " + key + " to " + dr);
        }

        /*
         * Subtract the server and share from the pathConsumed so that
         * it refects the part of the relative path consumed and not
         * the entire path.
         */
        dri.stripPathConsumed(1 + server.length() + 1 + share.length());

        synchronized ( this.referralsLock ) {
            if ( this.referrals != null && ( System.currentTimeMillis() + 10000 ) > this.referrals.expiration ) {
                this.referrals = null;
            }
            if ( this.referrals == null ) {
                this.referrals = new CacheEntry<>(tc.getConfig().getDfsTtl());
            }
            this.referrals.map.put(key, dri);
        }

    }
}
