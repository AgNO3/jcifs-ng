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

import org.apache.log4j.Logger;

import jcifs.CIFSContext;
import jcifs.UniAddress;


public class Dfs {

    private static class CacheEntry <T> {

        long expiration;
        Map<String, T> map;


        CacheEntry ( long ttl ) {
            this.expiration = System.currentTimeMillis() + ttl * 1000L;
            this.map = new HashMap<>();
        }
    }

    private static final Logger log = Logger.getLogger(Dfs.class);

    private CacheEntry<DfsReferral> negativeEntry;
    private CacheEntry<Map<String, CacheEntry<DfsReferral>>> _domains = null; /* aka trusted domains cache */
    private CacheEntry<DfsReferral> referrals = null;


    /**
     * 
     */
    public Dfs ( CIFSContext tc ) {
        this.negativeEntry = new CacheEntry<>(tc.getConfig().getDfsTtl());
    }


    public Map<String, Map<String, CacheEntry<DfsReferral>>> getTrustedDomains ( CIFSContext tf ) throws SmbAuthException {
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
            UniAddress addr = UniAddress.getByName(authDomain, true, tf);
            SmbTransport trans = tf.getTransportPool().getSmbTransport(tf, addr, 0);
            CacheEntry<Map<String, CacheEntry<DfsReferral>>> entry = new CacheEntry<>(tf.getConfig().getDfsTtl() * 10L);
            DfsReferral dr = trans.getDfsReferrals(tf, "", 0);
            if ( dr != null ) {
                DfsReferral start = dr;
                do {
                    String domain = dr.server.toLowerCase();
                    entry.map.put(domain, new HashMap<String, CacheEntry<DfsReferral>>());
                    dr = dr.next;
                }
                while ( dr != start );

                this._domains = entry;
                return this._domains.map;
            }
        }
        catch ( IOException ioe ) {
            log.debug("getting trusted domains failed: " + tf.getCredentials().getUserDomain(), ioe);
            if ( tf.getConfig().isDfsStrictView() && ioe instanceof SmbAuthException ) {
                throw (SmbAuthException) ioe;
            }
        }
        return null;
    }


    public boolean isTrustedDomain ( String domain, CIFSContext tf ) throws SmbAuthException {
        Map<String, Map<String, CacheEntry<DfsReferral>>> domains = getTrustedDomains(tf);
        if ( domains == null )
            return false;
        domain = domain.toLowerCase();
        return domains.get(domain) != null;
    }


    public SmbTransport getDc ( String domain, CIFSContext tf ) throws SmbAuthException {
        if ( tf.getConfig().isDfsDisabled() )
            return null;

        try {
            UniAddress addr = UniAddress.getByName(domain, true, tf);
            SmbTransport trans = tf.getTransportPool().getSmbTransport(tf, addr, 0);
            DfsReferral dr = trans.getDfsReferrals(tf, "\\" + domain, 1);
            if ( dr != null ) {
                DfsReferral start = dr;
                IOException e = null;

                do {
                    try {
                        return tf.getTransportPool().getSmbTransport(tf, UniAddress.getByName(dr.server, tf), 0);
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
        catch ( IOException ioe ) {
            log.debug("Getting domain controller failed", ioe);
            if ( tf.getConfig().isDfsStrictView() && ioe instanceof SmbAuthException ) {
                throw (SmbAuthException) ioe;
            }
        }
        return null;
    }


    public DfsReferral getReferral ( CIFSContext tf, SmbTransport trans, String domain, String root, String path ) throws SmbAuthException {
        if ( tf.getConfig().isDfsDisabled() )
            return null;

        try {
            String p = "\\" + domain + "\\" + root;
            if ( path != null )
                p += path;
            DfsReferral dr = trans.getDfsReferrals(tf, p, 0);
            if ( dr != null )
                return dr;
        }
        catch ( IOException ioe ) {
            log.debug("Getting referral failed", ioe);
            if ( tf.getConfig().isDfsStrictView() && ioe instanceof SmbAuthException ) {
                throw (SmbAuthException) ioe;
            }
        }
        return null;
    }


    public synchronized DfsReferral resolve ( String domain, String root, String path, CIFSContext tf ) throws SmbAuthException {
        DfsReferral dr = null;
        long now = System.currentTimeMillis();

        if ( tf.getConfig().isDfsDisabled() || root.equals("IPC$") ) {
            return null;
        }
        /*
         * domains that can contain DFS points to maps of roots for each
         */
        Map<String, Map<String, CacheEntry<DfsReferral>>> domains = getTrustedDomains(tf);
        if ( domains != null ) {
            domain = domain.toLowerCase();
            /*
             * domain-based DFS root shares to links for each
             */
            Map<String, CacheEntry<DfsReferral>> roots = domains.get(domain);
            if ( roots != null ) {
                SmbTransport trans = null;

                root = root.toLowerCase();

                /*
                 * The link entries contain maps of referrals by path representing DFS links.
                 * Note that paths are relative to the root like "\" and not "\example.com\root".
                 */
                CacheEntry<DfsReferral> links = roots.get(root);
                if ( links != null && now > links.expiration ) {
                    roots.remove(root);
                    links = null;
                }

                if ( links == null ) {
                    if ( ( trans = getDc(domain, tf) ) == null )
                        return null;

                    dr = getReferral(tf, trans, domain, root, path);
                    if ( dr != null ) {
                        int len = 1 + domain.length() + 1 + root.length();

                        links = new CacheEntry<>(0L);

                        DfsReferral tmp = dr;
                        do {
                            if ( path == null ) {
                                /*
                                 * Store references to the map and key so that
                                 * SmbFile.resolveDfs can re-insert the dr list with
                                 * the dr that was successful so that subsequent
                                 * attempts to resolve DFS use the last successful
                                 * referral first.
                                 */
                                tmp.map = links.map;
                                tmp.key = "\\";
                            }
                            tmp.pathConsumed -= len;
                            tmp = tmp.next;
                        }
                        while ( tmp != dr );

                        if ( dr.key != null )
                            links.map.put(dr.key, dr);

                        roots.put(root, links);
                    }
                    else if ( path == null ) {
                        roots.put(root, this.negativeEntry);
                    }
                }
                else if ( links == this.negativeEntry ) {
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
                        links.map.remove(link);
                        dr = null;
                    }

                    if ( dr == null ) {
                        if ( trans == null )
                            if ( ( trans = getDc(domain, tf) ) == null )
                                return null;
                        dr = getReferral(tf, trans, domain, root, path);
                        if ( dr != null ) {
                            dr.pathConsumed -= 1 + domain.length() + 1 + root.length();
                            dr.link = link;
                            links.map.put(link, dr);
                        }
                    }
                }
            }
        }

        if ( dr == null && path != null ) {
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
            if ( path.equals("\\") == false )
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


    synchronized void insert ( String path, CIFSContext tc, DfsReferral dr ) {
        int s1, s2;
        String server, share, key;

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

        /*
         * Subtract the server and share from the pathConsumed so that
         * it refects the part of the relative path consumed and not
         * the entire path.
         */
        dr.pathConsumed -= 1 + server.length() + 1 + share.length();

        if ( this.referrals != null && ( System.currentTimeMillis() + 10000 ) > this.referrals.expiration ) {
            this.referrals = null;
        }
        if ( this.referrals == null ) {
            this.referrals = new CacheEntry<>(0);
        }
        this.referrals.map.put(key, dr);
    }
}
