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
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.DfsReferralData;
import jcifs.DfsResolver;
import jcifs.SmbTransport;
import jcifs.internal.dfs.DfsReferralDataImpl;
import jcifs.internal.dfs.DfsReferralDataInternal;


/**
 * Caching DFS resolver implementation
 * 
 * @internal
 */
public class DfsImpl implements DfsResolver {

    private static final DfsReferralDataImpl NEGATIVE_ENTRY = new DfsReferralDataImpl();

    private static class CacheEntry <T> {

        long expiration;
        Map<String, T> map;


        CacheEntry ( long ttl ) {
            this.expiration = System.currentTimeMillis() + ttl * 1000L;
            this.map = new ConcurrentHashMap<>();
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

    private final Map<String, CacheEntry<DfsReferralDataInternal>> dcCache = new HashMap<>();
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
                    initial = trans.getDfsReferrals(tf.withAnonymousCredentials(), "", trans.getRemoteHostName(), authDomain, 0);
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
            domain = domain.toLowerCase(Locale.ROOT);
            return domains.get(domain) != null;
        }
    }


    private DfsReferralData getDcReferrals ( CIFSContext tf, String domain ) throws SmbAuthException {
        if ( tf.getConfig().isDfsDisabled() )
            return null;
        String dom = domain.toLowerCase(Locale.ROOT);
        synchronized ( this.dcLock ) {
            CacheEntry<DfsReferralDataInternal> ce = this.dcCache.get(dom);
            if ( ce != null && System.currentTimeMillis() > ce.expiration ) {
                ce = null;
            }
            if ( ce != null ) {
                DfsReferralDataInternal ri = ce.map.get(DC_ENTRY);
                if ( ri == NEGATIVE_ENTRY ) {
                    return null;
                }
                return ri;
            }
            ce = new CacheEntry<>(tf.getConfig().getDfsTtl());
            try {
                try ( SmbTransportInternal trans = tf.getTransportPool().getSmbTransport(tf, domain, 0, false, false)
                        .unwrap(SmbTransportInternal.class) ) {
                    synchronized ( trans ) {
                        DfsReferralData dr = trans.getDfsReferrals(tf.withAnonymousCredentials(), "\\" + dom, domain, dom, 1);

                        if ( dr != null ) {
                            if ( log.isDebugEnabled() ) {
                                log.debug("Got DC referral " + dr);
                            }
                            DfsReferralDataInternal dri = dr.unwrap(DfsReferralDataInternal.class);
                            ce.map.put(DC_ENTRY, dri);
                            this.dcCache.put(dom, ce);
                            return dr;
                        }
                    }
                }
            }
            catch ( IOException ioe ) {
                if ( log.isDebugEnabled() ) {
                    log.debug(String.format("Getting domain controller for %s failed", domain), ioe);
                }
                ce.map.put(DC_ENTRY, NEGATIVE_ENTRY);
                if ( tf.getConfig().isDfsStrictView() && ioe instanceof SmbAuthException ) {
                    throw (SmbAuthException) ioe;
                }
            }
            ce.map.put(DC_ENTRY, NEGATIVE_ENTRY);
            this.dcCache.put(dom, ce);
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
                    if ( dr.getServer() != null && !dr.getServer().isEmpty() ) {
                        try {
                            SmbTransportImpl transport = tf.getTransportPool().getSmbTransport(
                                tf,
                                dr.getServer(),
                                0,
                                false,
                                !tf.getCredentials().isAnonymous() && tf.getConfig().isSigningEnabled() && tf.getConfig().isIpcSigningEnforced())
                                    .unwrap(SmbTransportImpl.class);
                            transport.ensureConnected();
                            return transport;
                        }
                        catch ( IOException ex ) {
                            log.debug("Connection failed " + dr.getServer(), ex);
                            e = ex;
                            dr = dr.next();
                            continue;
                        }
                    }

                    log.debug("No server name in referral");
                    return null;
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


    protected DfsReferralDataInternal getReferral ( CIFSContext tf, SmbTransportInternal trans, String target, String targetDomain, String targetHost,
            String root, String path ) throws SmbAuthException {
        if ( tf.getConfig().isDfsDisabled() )
            return null;

        String p = "\\" + target + "\\" + root;
        if ( path != null ) {
            p += path;
        }
        try {
            if ( log.isDebugEnabled() ) {
                log.debug("Fetching referral for " + p);
            }
            DfsReferralData dr = trans.getDfsReferrals(tf, p, targetHost, targetDomain, 0);
            if ( dr != null ) {

                if ( log.isDebugEnabled() ) {
                    log.debug(String.format("Referral for %s: %s", p, dr));
                }

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
        return resolve(tf, domain, root, path, 5);
    }


    private DfsReferralData resolve ( CIFSContext tf, String domain, String root, String path, int depthLimit ) throws SmbAuthException {

        if ( tf.getConfig().isDfsDisabled() || root == null || root.equals("IPC$") || depthLimit <= 0 ) {
            return null;
        }

        if ( domain == null ) {
            return null;
        }

        domain = domain.toLowerCase();

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
                    dumpReferralCache(domains);
                }

                root = root.toLowerCase();
                /*
                 * domain-based DFS root shares to links for each
                 */
                Map<String, CacheEntry<DfsReferralDataInternal>> roots = domains.get(domain);
                if ( roots != null ) {
                    dr = getLinkReferral(tf, domain, root, path, now, roots);
                }

                if ( tf.getConfig().isDfsConvertToFQDN() && dr instanceof DfsReferralDataImpl ) {
                    ( (DfsReferralDataImpl) dr ).fixupDomain(domain);
                }
            }
        }

        if ( dr == null && path != null ) {
            dr = getStandaloneCached(domain, root, path, now);
        }

        if ( dr != null && dr.isIntermediate() ) {
            dr = resolveIntermediates(tf, path, depthLimit, dr);
        }

        return dr;

    }


    /**
     * @param tf
     * @param path
     * @param depthLimit
     * @param dr
     * @return
     * @throws SmbAuthException
     */
    private DfsReferralDataInternal resolveIntermediates ( CIFSContext tf, String path, int depthLimit, DfsReferralDataInternal dr )
            throws SmbAuthException {
        DfsReferralDataInternal res = null;
        DfsReferralDataInternal start = dr;
        DfsReferralDataInternal r = start;
        do {
            r = start.next();
            String refPath = dr.getPath() != null ? '\\' + dr.getPath() : "";
            String nextPath = refPath + ( path != null ? path.substring(r.getPathConsumed()) : "" );
            if ( log.isDebugEnabled() ) {
                log.debug(
                    String.format(
                        "Intermediate referral, server %s share %s refPath %s origPath %s nextPath %s",
                        r.getServer(),
                        r.getShare(),
                        r.getPath(),
                        path,
                        nextPath));
            }
            DfsReferralData nextstart = resolve(tf, r.getServer(), r.getShare(), nextPath, depthLimit - 1);
            DfsReferralData next = nextstart;

            if ( next != null ) {
                do {
                    if ( log.isDebugEnabled() ) {
                        log.debug("Next referral is " + next);
                    }
                    if ( res == null ) {
                        res = r.combine(next);
                    }
                    else {
                        res.append(r.combine(next));
                    }
                }
                while ( next != nextstart );
            }
        }
        while ( r != start );

        if ( res != null ) {
            return res;
        }

        return dr;
    }


    /**
     * @param domains
     */
    private static void dumpReferralCache ( Map<String, Map<String, CacheEntry<DfsReferralDataInternal>>> domains ) {
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


    /**
     * @param tf
     * @param domain
     * @param root
     * @param path
     * @param dr
     * @param now
     * @param roots
     * @return
     * @throws SmbAuthException
     */
    private DfsReferralDataInternal getLinkReferral ( CIFSContext tf, String domain, String root, String path, long now,
            Map<String, CacheEntry<DfsReferralDataInternal>> roots ) throws SmbAuthException {
        DfsReferralDataInternal dr = null;
        if ( log.isTraceEnabled() ) {
            log.trace("Is a domain referral for " + domain);
        }

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
            log.trace("Loadings roots");
            String refServerName = domain;
            dr = fetchRootReferral(tf, domain, root, path, refServerName);
            links = cacheRootReferral(tf, domain, root, path, roots, dr, links);
        }
        else if ( links instanceof NegativeCacheEntry ) {
            links = null;
        }

        if ( links != null ) {
            return getLinkReferral(tf, domain, root, path, dr, now, links);
        }
        return dr;
    }


    /**
     * @param tf
     * @param domain
     * @param root
     * @param path
     * @param roots
     * @param dr
     * @param links
     * @return
     */
    private static CacheEntry<DfsReferralDataInternal> cacheRootReferral ( CIFSContext tf, String domain, String root, String path,
            Map<String, CacheEntry<DfsReferralDataInternal>> roots, DfsReferralDataInternal dr, CacheEntry<DfsReferralDataInternal> links ) {
        if ( dr != null ) {
            links = new CacheEntry<>(tf.getConfig().getDfsTtl());
            DfsReferralDataInternal tmp = dr;
            do {
                int consumedRoot = 1 + domain.length() + 1 + root.length();
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
                log.debug("Stripping " + consumedRoot + " root " + root + " domain " + domain + " referral " + tmp);
                tmp.stripPathConsumed(consumedRoot);

                if ( path != null && tmp.getPathConsumed() > 0 ) {
                    int actualPathConsumed = tmp.getPathConsumed();
                    String link = path.substring(0, actualPathConsumed);
                    tmp.setKey(link);
                    links.map.put(dr.getKey(), dr);
                }

                tmp = tmp.next();
            }
            while ( tmp != dr );

            if ( log.isDebugEnabled() ) {
                log.debug("Have referral " + dr);
            }

            roots.put(root, links);
        }
        else if ( path == null ) {
            roots.put(root, new NegativeCacheEntry<DfsReferralDataInternal>(tf.getConfig().getDfsTtl()));
        }
        return links;
    }


    /**
     * @param tf
     * @param domain
     * @param root
     * @param path
     * @param refServerName
     * @return
     * @throws SmbAuthException
     */
    private DfsReferralDataInternal fetchRootReferral ( CIFSContext tf, String domain, String root, String path, String refServerName )
            throws SmbAuthException {
        DfsReferralDataInternal dr;
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
                catch ( IOException e ) {
                    log.warn("Failed to connect to domain controller", e);
                }
                dr = getReferral(tf, trans, domain, domain, refServerName, root, path);
            }
        }

        if ( log.isTraceEnabled() ) {
            log.trace("Have DC referral " + dr);
        }

        if ( dr != null && path == null && domain.equals(dr.getServer()) && root.equals(dr.getShare()) ) {
            // If we do cache these we never get to the properly cached
            // standalone referral we might have.
            log.warn("Dropping self-referential referral " + dr);
            dr = null;
        }
        return dr;
    }


    /**
     * @param tf
     * @param domain
     * @param root
     * @param path
     * @param dr
     * @param now
     * @param links
     * @return
     * @throws SmbAuthException
     */
    private DfsReferralDataInternal getLinkReferral ( CIFSContext tf, String domain, String root, String path, DfsReferralDataInternal dr, long now,
            CacheEntry<DfsReferralDataInternal> links ) throws SmbAuthException {
        String link;

        if ( path == null || path.length() <= 1 ) {
            /*
             * Lookup the domain based DFS root target referral. Note the
             * path is just "\" and not "\example.com\root".
             */
            link = "\\";
        }
        else if ( path.charAt(path.length() - 1) == '\\' ) {
            // strip trailing slash
            link = path.substring(0, path.length() - 1);
        }
        else {
            link = path;
        }

        if ( log.isTraceEnabled() ) {
            log.trace("Initial link is " + link);
        }

        if ( dr == null || !link.equals(dr.getLink()) ) {
            while ( true ) {
                dr = links.map.get(link);

                if ( dr != null ) {
                    if ( log.isTraceEnabled() ) {
                        log.trace("Found at " + link);
                    }
                    break;
                }

                // walk up trying to find a match, do not go up to the root
                int nextSep = link.lastIndexOf('\\');
                if ( nextSep > 0 ) {
                    link = link.substring(0, nextSep);
                }
                else {
                    if ( log.isTraceEnabled() ) {
                        log.trace("Not found " + link);
                    }
                    break;
                }
            }
        }

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

                dr = getReferral(tf, trans, domain, domain, trans.getRemoteHostName(), root, path);
                if ( dr != null ) {

                    if ( tf.getConfig().isDfsConvertToFQDN() && dr instanceof DfsReferralDataImpl ) {
                        ( (DfsReferralDataImpl) dr ).fixupDomain(domain);
                    }

                    dr.stripPathConsumed(1 + domain.length() + 1 + root.length());

                    if ( dr.getPathConsumed() > ( path != null ? path.length() : 0 ) ) {
                        log.error("Consumed more than we provided");
                    }

                    link = path != null && dr.getPathConsumed() > 0 ? path.substring(0, dr.getPathConsumed()) : "\\";
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
            log.trace("Have cached referral for " + dr.getLink() + " " + dr);
        }
        return dr;
    }


    /**
     * @param domain
     * @param root
     * @param path
     * @param dr
     * @param now
     * @return
     */
    private DfsReferralDataInternal getStandaloneCached ( String domain, String root, String path, long now ) {
        if ( log.isTraceEnabled() ) {
            log.trace("No match for domain based root, checking standalone " + domain);
        }
        /*
         * We did not match a domain based root. Now try to match the
         * longest path in the list of stand-alone referrals.
         */

        CacheEntry<DfsReferralDataInternal> refs;
        synchronized ( this.referralsLock ) {
            refs = this.referrals;
            if ( refs == null || now > refs.expiration ) {
                refs = new CacheEntry<>(0);
            }
            this.referrals = refs;
        }
        String key = "\\" + domain + "\\" + root;
        if ( !path.equals("\\") ) {
            key += path;
        }

        key = key.toLowerCase(Locale.ROOT);

        Iterator<String> iter = refs.map.keySet().iterator();
        int searchLen = key.length();
        while ( iter.hasNext() ) {
            String cachedKey = iter.next();
            int cachedKeyLen = cachedKey.length();

            boolean match = false;
            if ( cachedKeyLen == searchLen ) {
                match = cachedKey.equals(key);
            }
            else if ( cachedKeyLen < searchLen ) {
                match = key.startsWith(cachedKey);
            }
            else if ( log.isTraceEnabled() ) {
                log.trace(key + " vs. " + cachedKey);
            }

            if ( match ) {
                if ( log.isDebugEnabled() ) {
                    log.debug("Matched " + cachedKey);
                }
                return refs.map.get(cachedKey);
            }
        }
        if ( log.isTraceEnabled() ) {
            log.trace("No match for " + key);
        }
        return null;
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

        if ( s1 < 0 || s2 < 0 ) {
            log.error("Invalid UNC path " + path);
            return;
        }

        String server = path.substring(1, s1).toLowerCase(Locale.ROOT);
        String share = path.substring(s1 + 1, s2);
        String key = path.substring(0, dr.getPathConsumed()).toLowerCase(Locale.ROOT);

        DfsReferralDataInternal dri = (DfsReferralDataInternal) dr;

        if ( tc.getConfig().isDfsConvertToFQDN() ) {
            dri.fixupHost(server);
        }

        if ( log.isDebugEnabled() ) {
            log.debug("Adding key " + key + " to " + dr);
        }

        /*
         * Subtract the server and share from the pathConsumed so that
         * it reflects the part of the relative path consumed and not
         * the entire path.
         */
        dri.stripPathConsumed(1 + server.length() + 1 + share.length());

        if ( key.charAt(key.length() - 1) != '\\' ) {
            key += '\\';
        }

        if ( log.isDebugEnabled() ) {
            log.debug("Key is " + key);
        }

        CacheEntry<DfsReferralDataInternal> refs = this.referrals;
        synchronized ( this.referralsLock ) {
            if ( refs == null || ( System.currentTimeMillis() + 10000 ) > refs.expiration ) {
                refs = new CacheEntry<>(tc.getConfig().getDfsTtl());
            }
            this.referrals = refs;
        }
        refs.map.put(key, dri);
    }
}
