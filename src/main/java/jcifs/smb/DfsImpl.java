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
import java.util.Map;
import java.util.Map.Entry;

import org.apache.log4j.Logger;

import jcifs.CIFSContext;
import jcifs.netbios.UniAddress;


/**
 * 
 *
 */
public class DfsImpl implements Dfs {

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

    private static final Logger log = Logger.getLogger(DfsImpl.class);

    private CacheEntry<Map<String, CacheEntry<DfsReferral>>> _domains = null; /* aka trusted domains cache */
    private final Object domainsLock = new Object();

    private CacheEntry<DfsReferral> referrals = null;
    private final Object referralsLock = new Object();


    /**
     * @param tc
     * 
     */
    public DfsImpl ( CIFSContext tc ) {}


    private Map<String, Map<String, CacheEntry<DfsReferral>>> getTrustedDomains ( CIFSContext tf ) throws SmbAuthException {
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
            SmbTransport trans = getDc(tf, authDomain);
            CacheEntry<Map<String, CacheEntry<DfsReferral>>> entry = new CacheEntry<>(tf.getConfig().getDfsTtl() * 10L);
            DfsReferral dr = null;
            if ( trans != null ) {
                dr = trans.getDfsReferrals(tf, "", 0);
            }
            if ( dr != null ) {
                DfsReferral start = dr;
                do {
                    String domain = dr.server.toLowerCase();
                    entry.map.put(domain, new HashMap<String, CacheEntry<DfsReferral>>());
                    if ( log.isTraceEnabled() ) {
                        log.trace("Inserting cache entry for domain " + domain + ": " + dr);
                    }
                    dr = dr.next;
                }
                while ( dr != start );

                this._domains = entry;
                return this._domains.map;
            }
        }
        catch ( IOException ioe ) {
            log.debug("getting trusted domains failed: " + tf.getCredentials().getUserDomain(), ioe);
            CacheEntry<Map<String, CacheEntry<DfsReferral>>> entry = new CacheEntry<>(tf.getConfig().getDfsTtl() * 10L);
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
     * @see jcifs.smb.Dfs#isTrustedDomain(jcifs.CIFSContext, java.lang.String)
     */
    @Override
    public boolean isTrustedDomain ( CIFSContext tf, String domain ) throws SmbAuthException {
        synchronized ( this.domainsLock ) {
            Map<String, Map<String, CacheEntry<DfsReferral>>> domains = getTrustedDomains(tf);
            if ( domains == null )
                return false;
            domain = domain.toLowerCase();
            return domains.get(domain) != null;
        }
    }


    /**
     * 
     * {@inheritDoc}
     *
     * @see jcifs.smb.Dfs#getDc(jcifs.CIFSContext, java.lang.String)
     */
    @Override
    public SmbTransport getDc ( CIFSContext tf, String domain ) throws SmbAuthException {
        if ( tf.getConfig().isDfsDisabled() )
            return null;

        try {
            UniAddress addr = tf.getNameServiceClient().getByName(domain, true);
            SmbTransport trans = tf.getTransportPool().getSmbTransport(tf, addr, 0, false);
            synchronized ( trans ) {
                DfsReferral dr = trans.getDfsReferrals(tf.withAnonymousCredentials(), "\\" + domain, 1);
                if ( dr != null ) {
                    DfsReferral start = dr;
                    IOException e = null;
                    do {
                        try {
                            if ( dr.server != null && dr.server.length() > 0 ) {
                                return tf.getTransportPool().getSmbTransport(
                                    tf,
                                    tf.getNameServiceClient().getByName(dr.server),
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

                        dr = dr.next;
                    }
                    while ( dr != start );

                    throw e;
                }
            }
        }
        catch ( IOException ioe ) {
            if ( log.isDebugEnabled() ) {
                log.debug(String.format("Getting domain controller for %s failed", domain), ioe);
            }
            if ( tf.getConfig().isDfsStrictView() && ioe instanceof SmbAuthException ) {
                throw (SmbAuthException) ioe;
            }
        }
        return null;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.Dfs#getReferral(jcifs.CIFSContext, jcifs.smb.SmbTransport, java.lang.String, java.lang.String,
     *      java.lang.String)
     */
    @Override
    public DfsReferral getReferral ( CIFSContext tf, SmbTransport trans, String domain, String root, String path ) throws SmbAuthException {
        if ( tf.getConfig().isDfsDisabled() )
            return null;

        String p = "\\\\" + domain + "\\" + root;
        if ( path != null )
            p += path;
        try {
            if ( log.isDebugEnabled() ) {
                log.debug("Fetching referral for " + p);
            }
            DfsReferral dr = trans.getDfsReferrals(tf, p, 0);
            if ( dr != null ) {
                return dr;
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
     * @see jcifs.smb.Dfs#resolve(jcifs.CIFSContext, java.lang.String, java.lang.String, java.lang.String)
     */
    @Override
    public DfsReferral resolve ( CIFSContext tf, String domain, String root, String path ) throws SmbAuthException {

        if ( tf.getConfig().isDfsDisabled() || root.equals("IPC$") ) {
            return null;
        }

        if ( domain == null ) {
            return null;
        }

        if ( log.isTraceEnabled() ) {
            log.trace(String.format("Resolving \\%s\\%s%s", domain, root, path != null ? path : ""));
        }

        DfsReferral dr = null;
        long now = System.currentTimeMillis();
        synchronized ( this.domainsLock ) {
            /*
             * domains that can contain DFS points to maps of roots for each
             */
            Map<String, Map<String, CacheEntry<DfsReferral>>> domains = getTrustedDomains(tf);

            if ( domains != null ) {

                if ( log.isTraceEnabled() ) {
                    for ( Entry<String, Map<String, CacheEntry<DfsReferral>>> entry : domains.entrySet() ) {
                        log.trace("Domain " + entry.getKey());
                        for ( Entry<String, CacheEntry<DfsReferral>> entry2 : entry.getValue().entrySet() ) {
                            log.trace("  Root " + entry2.getKey());
                            if ( entry2.getValue().map != null ) {
                                for ( Entry<String, DfsReferral> entry3 : entry2.getValue().map.entrySet() ) {
                                    DfsReferral start = entry3.getValue();
                                    DfsReferral r = start;
                                    do {
                                        log.trace("    " + entry3.getKey() + " => " + entry3.getValue());
                                        r = start.next;
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
                Map<String, CacheEntry<DfsReferral>> roots = domains.get(domain);
                if ( roots != null ) {
                    SmbTransport trans = null;

                    root = root.toLowerCase();

                    if ( log.isTraceEnabled() ) {
                        log.trace("Resolving root " + root);
                    }
                    /*
                     * The link entries contain maps of referrals by path representing DFS links.
                     * Note that paths are relative to the root like "\" and not "\example.com\root".
                     */
                    CacheEntry<DfsReferral> links = roots.get(root);
                    if ( links != null && now > links.expiration ) {
                        if ( log.isDebugEnabled() ) {
                            log.debug("Removing expired " + links.map);
                        }
                        roots.remove(root);
                        links = null;
                    }

                    if ( links == null ) {
                        log.trace("Loadings links");
                        if ( ( trans = getDc(tf, domain) ) == null )
                            return null;

                        dr = getReferral(tf, trans, domain, root, path);
                        if ( log.isTraceEnabled() ) {
                            log.trace("Have referral " + dr);
                        }

                        // This is most certainly not the correct behaviour
                        //
                        // I guess what needs to be done here is properly handle name list referrals so that
                        // the target name will have already been replaced with a domain controller name.
                        if ( path == null && domain.equals(dr.server) && root.equals(dr.share) ) {
                            if ( !dr.server.equals(trans.tconHostName) ) {
                                // this is a hack
                                dr.server = trans.tconHostName;
                                if ( log.isDebugEnabled() ) {
                                    log.debug("Adjusting self-referential domain referral to domain controller " + dr.server);
                                }
                            }
                            else {
                                // If we do cache these we never get to the properly cached
                                // standalone referral we might have.
                                if ( log.isDebugEnabled() ) {
                                    log.debug("Adjusting self-referential referral " + dr);
                                }
                                dr = null;
                            }
                        }

                        if ( dr != null ) {
                            int len = 1 + domain.length() + 1 + root.length();

                            links = new CacheEntry<>(tf.getConfig().getDfsTtl());

                            DfsReferral tmp = dr;
                            do {
                                if ( path == null || path.length() == 0 ) {

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
                                    tmp.map = links.map;
                                    tmp.key = "\\";
                                    len++;
                                }
                                tmp.pathConsumed -= len;
                                tmp = tmp.next;
                            }
                            while ( tmp != dr );

                            if ( log.isDebugEnabled() ) {
                                log.debug("Have referral " + dr);
                            }

                            if ( dr.key != null )
                                links.map.put(dr.key, dr);

                            roots.put(root, links);
                        }
                        else if ( path == null ) {
                            roots.put(root, new NegativeCacheEntry<DfsReferral>(tf.getConfig().getDfsTtl()));
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
                        if ( dr != null && now > dr.expiration ) {
                            log.trace("Expiring links " + link);
                            links.map.remove(link);
                            dr = null;
                        }

                        if ( dr == null ) {

                            if ( trans == null )
                                if ( ( trans = getDc(tf, domain) ) == null )
                                    return null;

                            dr = getReferral(tf, trans, domain, root, path);
                            if ( dr != null ) {

                                dr.pathConsumed -= 1 + domain.length() + 1 + root.length();
                                dr.link = link;
                                if ( log.isTraceEnabled() ) {
                                    log.trace("Have referral " + dr);
                                }
                                links.map.put(link, dr);
                            }
                            else {
                                log.trace("No referral found for " + link);
                            }
                        }
                        else {
                            log.trace("Have cached referral " + dr);
                        }
                    }
                }
            }
        }

        if ( dr == null && path != null ) {
            log.trace("No match for domain based root, checking standalone");
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
    public synchronized void cache ( CIFSContext tc, String path, DfsReferral dr ) {
        int s1, s2;
        String server, share, key;

        log.debug("Inserting referral for " + path);

        if ( tc.getConfig().isDfsDisabled() )
            return;

        s1 = path.indexOf('\\', 1);
        s2 = path.indexOf('\\', s1 + 1);
        server = path.substring(1, s1);
        share = path.substring(s1 + 1, s2);

        key = path.substring(0, dr.pathConsumed).toLowerCase();

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

        if ( log.isDebugEnabled() ) {
            log.debug("Adding key " + key + " to " + dr);
        }

        /*
         * Subtract the server and share from the pathConsumed so that
         * it refects the part of the relative path consumed and not
         * the entire path.
         */
        dr.pathConsumed -= 1 + server.length() + 1 + share.length();

        synchronized ( this.referralsLock ) {
            if ( this.referrals != null && ( System.currentTimeMillis() + 10000 ) > this.referrals.expiration ) {
                this.referrals = null;
            }
            if ( this.referrals == null ) {
                this.referrals = new CacheEntry<>(tc.getConfig().getDfsTtl());
            }
            this.referrals.map.put(key, dr);
        }

    }
}
