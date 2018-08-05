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


import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.Address;
import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.DfsReferralData;
import jcifs.NetbiosAddress;
import jcifs.RuntimeCIFSException;
import jcifs.SmbConstants;
import jcifs.SmbResourceLocator;
import jcifs.internal.util.StringUtil;
import jcifs.netbios.NbtAddress;
import jcifs.netbios.UniAddress;


/**
 * 
 * 
 * This mainly tracks two locations:
 * - canonical URL path: path component of the URL: this is used to reconstruct URLs to resources and is not adjusted by
 * DFS referrals. (E.g. a resource with a DFS root's parent will still point to the DFS root not the share it's actually
 * located in).
 * - share + uncpath within it: This is the relevant information for most SMB requests. Both are adjusted by DFS
 * referrals. Nested resources will inherit the information already resolved by the parent resource.
 * 
 * Invariant:
 * A directory resource must have a trailing slash/backslash for both URL and UNC path at all times.
 * 
 * @author mbechler
 *
 */
class SmbResourceLocatorImpl implements SmbResourceLocatorInternal, Cloneable {

    private static final Logger log = LoggerFactory.getLogger(SmbResourceLocatorImpl.class);

    private final URL url;

    private DfsReferralData dfsReferral = null; // For getDfsPath() and getServerWithDfs()

    private String unc; // Initially null; set by getUncPath; never ends with '/'
    private String canon; // Initially null; set by getUncPath; dir must end with '/'
    private String share; // Can be null

    private Address[] addresses;
    private int addressIndex;
    private int type;

    private CIFSContext ctx;


    /**
     * 
     * @param ctx
     * @param u
     */
    public SmbResourceLocatorImpl ( CIFSContext ctx, URL u ) {
        this.ctx = ctx;
        this.url = u;
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#clone()
     */
    @Override
    protected SmbResourceLocatorImpl clone () {
        SmbResourceLocatorImpl loc = new SmbResourceLocatorImpl(this.ctx, this.url);
        loc.canon = this.canon;
        loc.share = this.share;
        loc.dfsReferral = this.dfsReferral;
        loc.unc = this.unc;
        if ( this.addresses != null ) {
            loc.addresses = new UniAddress[this.addresses.length];
            System.arraycopy(this.addresses, 0, loc.addresses, 0, this.addresses.length);
        }
        loc.addressIndex = this.addressIndex;
        loc.type = this.type;
        return loc;
    }


    /**
     * @param context
     * @param name
     */
    void resolveInContext ( SmbResourceLocator context, String name ) {
        String shr = context.getShare();
        if ( shr != null ) {
            this.dfsReferral = context.getDfsReferral();
        }
        int last = name.length() - 1;
        boolean trailingSlash = false;
        if ( last >= 0 && name.charAt(last) == '/' ) {
            trailingSlash = true;
            name = name.substring(0, last);
        }

        if ( shr == null ) {
            String[] nameParts = name.split("/");

            // server is set through URL, however it's still in the name
            int pos = 0;
            if ( context.getServer() == null ) {
                pos = 1;
            }

            // first remaining path element would be share
            if ( nameParts.length > pos ) {
                this.share = nameParts[ pos++ ];
            }

            // all other remaining path elements are actual path
            if ( nameParts.length > pos ) {
                String[] remainParts = new String[nameParts.length - pos];
                System.arraycopy(nameParts, pos, remainParts, 0, nameParts.length - pos);
                this.unc = "\\" + StringUtil.join("\\", remainParts) + ( trailingSlash ? "\\" : "" );
                this.canon = "/" + this.share + "/" + StringUtil.join("/", remainParts) + ( trailingSlash ? "/" : "" );
            }
            else {
                this.unc = "\\";
                if ( this.share != null ) {
                    this.canon = "/" + this.share + ( trailingSlash ? "/" : "" );
                }
                else {
                    this.canon = "/";
                }
            }
        }
        else {
            String uncPath = context.getUNCPath();
            if ( uncPath.equals("\\") ) {
                // context share != null, so the remainder is path
                this.unc = '\\' + name.replace('/', '\\') + ( trailingSlash ? "\\" : "" );
                this.canon = context.getURLPath() + name + ( trailingSlash ? "/" : "" );
                this.share = shr;
            }
            else {
                this.unc = uncPath + name.replace('/', '\\') + ( trailingSlash ? "\\" : "" );
                this.canon = context.getURLPath() + name + ( trailingSlash ? "/" : "" );
                this.share = shr;
            }
        }
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.SmbResourceLocator#getDfsReferral()
     */
    @Override
    public DfsReferralData getDfsReferral () {
        return this.dfsReferral;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.SmbResourceLocator#getName()
     */

    @Override
    public String getName () {
        String urlpath = getURLPath();
        String shr = getShare();
        if ( urlpath.length() > 1 ) {
            int i = urlpath.length() - 2;
            while ( urlpath.charAt(i) != '/' ) {
                i--;
            }
            return urlpath.substring(i + 1);
        }
        else if ( shr != null ) {
            return shr + '/';
        }
        else if ( this.url.getHost().length() > 0 ) {
            return this.url.getHost() + '/';
        }
        else {
            return "smb://";
        }
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.SmbResourceLocator#getParent()
     */
    @Override
    public String getParent () {
        String str = this.url.getAuthority();

        if ( str != null && !str.isEmpty() ) {
            StringBuffer sb = new StringBuffer("smb://");

            sb.append(str);

            String urlpath = getURLPath();
            if ( urlpath.length() > 1 ) {
                sb.append(urlpath);
            }
            else {

                sb.append('/');
            }

            str = sb.toString();

            int i = str.length() - 2;
            while ( str.charAt(i) != '/' ) {
                i--;
            }

            return str.substring(0, i + 1);
        }

        return "smb://";
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.SmbResourceLocator#getPath()
     */

    @Override
    public String getPath () {
        return this.url.toString();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.SmbResourceLocator#getCanonicalURL()
     */
    @Override
    public String getCanonicalURL () {
        String str = this.url.getAuthority();
        if ( str != null && !str.isEmpty() ) {
            return "smb://" + this.url.getAuthority() + this.getURLPath();
        }
        return "smb://";
    }


    @Override
    public String getUNCPath () {
        if ( this.unc == null ) {
            canonicalizePath();
        }
        return this.unc;
    }


    @Override
    public String getURLPath () {
        if ( this.unc == null ) {
            canonicalizePath();
        }
        return this.canon;
    }


    @Override
    public String getShare () {
        if ( this.unc == null ) {
            canonicalizePath();
        }
        return this.share;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.SmbResourceLocator#getServerWithDfs()
     */
    @Override
    public String getServerWithDfs () {
        if ( this.dfsReferral != null ) {
            return this.dfsReferral.getServer();
        }
        return getServer();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.SmbResourceLocator#getServer()
     */
    @Override
    public String getServer () {
        String str = this.url.getHost();
        if ( str.length() == 0 ) {
            return null;
        }
        return str;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.SmbResourceLocator#getDfsPath()
     */
    @Override
    public String getDfsPath () {
        if ( this.dfsReferral == null ) {
            return null;
        }
        return "smb:/" + this.dfsReferral.getServer() + "/" + this.dfsReferral.getShare() + this.getUNCPath().replace('\\', '/');
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.SmbResourceLocator#getPort()
     */
    @Override
    public int getPort () {
        return this.url.getPort();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.SmbResourceLocator#getURL()
     */
    @Override
    public URL getURL () {
        return this.url;
    }


    /**
     * 
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbResourceLocatorInternal#shouldForceSigning()
     */
    @Override
    public boolean shouldForceSigning () {
        return this.ctx.getConfig().isIpcSigningEnforced() && !this.ctx.getCredentials().isAnonymous() && isIPC();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.SmbResourceLocator#isIPC()
     */
    @Override
    public boolean isIPC () {
        String shr = this.getShare();
        if ( shr == null || "IPC$".equals(getShare()) ) {
            if ( log.isDebugEnabled() ) {
                log.debug("Share is IPC " + this.share);
            }
            return true;
        }
        return false;
    }


    /**
     * @param t
     */
    void updateType ( int t ) {
        this.type = t;
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.SmbResourceLocator#getType()
     */
    @Override
    public int getType () throws CIFSException {
        if ( this.type == 0 ) {
            if ( getUNCPath().length() > 1 ) {
                this.type = SmbConstants.TYPE_FILESYSTEM;
            }
            else if ( getShare() != null ) {
                if ( getShare().equals("IPC$") ) {
                    this.type = SmbConstants.TYPE_NAMED_PIPE;
                }
                else {
                    this.type = SmbConstants.TYPE_SHARE;
                }
            }
            else if ( this.url.getAuthority() == null || this.url.getAuthority().isEmpty() ) {
                this.type = SmbConstants.TYPE_WORKGROUP;
            }
            else {
                try {
                    NetbiosAddress nbaddr = getAddress().unwrap(NetbiosAddress.class);
                    if ( nbaddr != null ) {
                        int code = nbaddr.getNameType();
                        if ( code == 0x1d || code == 0x1b ) {
                            this.type = SmbConstants.TYPE_WORKGROUP;
                            return this.type;
                        }
                    }
                }
                catch ( CIFSException e ) {
                    if ( ! ( e.getCause() instanceof UnknownHostException ) ) {
                        throw e;
                    }
                    log.debug("Unknown host", e);
                }
                this.type = SmbConstants.TYPE_SERVER;
            }
        }
        return this.type;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.SmbResourceLocator#isWorkgroup()
     */
    @Override
    public boolean isWorkgroup () throws CIFSException {
        if ( this.type == SmbConstants.TYPE_WORKGROUP || this.url.getHost().length() == 0 ) {
            this.type = SmbConstants.TYPE_WORKGROUP;
            return true;
        }

        if ( getShare() == null ) {
            NetbiosAddress addr = getAddress().unwrap(NetbiosAddress.class);
            if ( addr != null ) {
                int code = addr.getNameType();
                if ( code == 0x1d || code == 0x1b ) {
                    this.type = SmbConstants.TYPE_WORKGROUP;
                    return true;
                }
            }
            this.type = SmbConstants.TYPE_SERVER;
        }
        return false;
    }


    @Override
    public Address getAddress () throws CIFSException {
        if ( this.addressIndex == 0 )
            return getFirstAddress();
        return this.addresses[ this.addressIndex - 1 ];
    }


    static String queryLookup ( String query, String param ) {
        char in[] = query.toCharArray();
        int i, ch, st, eq;

        st = eq = 0;
        for ( i = 0; i < in.length; i++ ) {
            ch = in[ i ];
            if ( ch == '&' ) {
                if ( eq > st ) {
                    String p = new String(in, st, eq - st);
                    if ( p.equalsIgnoreCase(param) ) {
                        eq++;
                        return new String(in, eq, i - eq);
                    }
                }
                st = i + 1;
            }
            else if ( ch == '=' ) {
                eq = i;
            }
        }
        if ( eq > st ) {
            String p = new String(in, st, eq - st);
            if ( p.equalsIgnoreCase(param) ) {
                eq++;
                return new String(in, eq, in.length - eq);
            }
        }

        return null;
    }


    Address getFirstAddress () throws CIFSException {
        this.addressIndex = 0;

        if ( this.addresses == null ) {
            String host = this.url.getHost();
            String path = this.url.getPath();
            String query = this.url.getQuery();
            try {
                if ( query != null ) {
                    String server = queryLookup(query, "server");
                    if ( server != null && server.length() > 0 ) {
                        this.addresses = new UniAddress[1];
                        this.addresses[ 0 ] = this.ctx.getNameServiceClient().getByName(server);
                    }
                    String address = queryLookup(query, "address");
                    if ( address != null && address.length() > 0 ) {
                        byte[] ip = java.net.InetAddress.getByName(address).getAddress();
                        this.addresses = new UniAddress[1];
                        this.addresses[ 0 ] = new UniAddress(java.net.InetAddress.getByAddress(host, ip));
                    }
                }
                else if ( host.length() == 0 ) {
                    try {
                        Address addr = this.ctx.getNameServiceClient().getNbtByName(NbtAddress.MASTER_BROWSER_NAME, 0x01, null);
                        this.addresses = new UniAddress[1];
                        this.addresses[ 0 ] = this.ctx.getNameServiceClient().getByName(addr.getHostAddress());
                    }
                    catch ( UnknownHostException uhe ) {
                        log.debug("Unknown host", uhe);
                        if ( this.ctx.getConfig().getDefaultDomain() == null ) {
                            throw uhe;
                        }
                        this.addresses = this.ctx.getNameServiceClient().getAllByName(this.ctx.getConfig().getDefaultDomain(), true);
                    }
                }
                else if ( path.length() == 0 || path.equals("/") ) {
                    this.addresses = this.ctx.getNameServiceClient().getAllByName(host, true);
                }
                else {
                    this.addresses = this.ctx.getNameServiceClient().getAllByName(host, false);
                }
            }
            catch ( UnknownHostException e ) {
                throw new CIFSException("Failed to lookup address for name " + host, e);
            }
        }

        return getNextAddress();
    }


    Address getNextAddress () {
        Address addr = null;
        if ( this.addressIndex < this.addresses.length )
            addr = this.addresses[ this.addressIndex++ ];
        return addr;
    }


    boolean hasNextAddress () {
        return this.addressIndex < this.addresses.length;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.SmbResourceLocator#isRoot()
     */
    @Override
    public boolean isRoot () {
        // length == 0 should not happen
        return getShare() == null && getUNCPath().length() <= 1;
    }


    boolean isRootOrShare () {
        // length == 0 should not happen
        return getUNCPath().length() <= 1;
    }


    /**
     * @throws MalformedURLException
     * 
     */
    private synchronized void canonicalizePath () {
        char[] in = this.url.getPath().toCharArray();
        char[] out = new char[in.length];
        int length = in.length, prefixLen = 0, state = 0;

        /*
         * The canonicalization routine
         */
        for ( int i = 0; i < length; i++ ) {
            switch ( state ) {
            case 0:
                if ( in[ i ] != '/' ) {
                    // Checked exception (e.g. MalformedURLException) would be better
                    // but this would be a nightmare API wise
                    throw new RuntimeCIFSException("Invalid smb: URL: " + this.url);
                }
                out[ prefixLen++ ] = in[ i ];
                state = 1;
                break;
            case 1:
                if ( in[ i ] == '/' ) {
                    break;
                }
                else if ( in[ i ] == '.' && ( ( i + 1 ) >= length || in[ i + 1 ] == '/' ) ) {
                    i++;
                    break;
                }
                else if ( ( i + 1 ) < length && in[ i ] == '.' && in[ i + 1 ] == '.' && ( ( i + 2 ) >= length || in[ i + 2 ] == '/' ) ) {
                    i += 2;
                    if ( prefixLen == 1 )
                        break;
                    do {
                        prefixLen--;
                    }
                    while ( prefixLen > 1 && out[ prefixLen - 1 ] != '/' );
                    break;
                }
                state = 2;
            case 2:
                if ( in[ i ] == '/' ) {
                    state = 1;
                }
                out[ prefixLen++ ] = in[ i ];
                break;
            }
        }

        this.canon = new String(out, 0, prefixLen);
        if ( prefixLen > 1 ) {
            prefixLen--;
            int firstSep = this.canon.indexOf('/', 1);
            if ( firstSep < 0 ) {
                this.share = this.canon.substring(1);
                this.unc = "\\";
            }
            else if ( firstSep == prefixLen ) {
                this.share = this.canon.substring(1, firstSep);
                this.unc = "\\";
            }
            else {
                this.share = this.canon.substring(1, firstSep);
                this.unc = this.canon.substring(firstSep, prefixLen + 1).replace('/', '\\');
            }
        }
        else {
            this.canon = "/";
            this.share = null;
            this.unc = "\\";
        }
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode () {
        int hash;
        try {
            hash = getAddress().hashCode();
        }
        catch ( CIFSException uhe ) {
            hash = getServer().toUpperCase().hashCode();
        }
        return hash + getURLPath().toUpperCase().hashCode();
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals ( Object obj ) {
        if ( ! ( obj instanceof SmbResourceLocatorImpl ) ) {
            return false;
        }

        SmbResourceLocatorImpl o = (SmbResourceLocatorImpl) obj;

        /*
         * If uncertain, pathNamesPossiblyEqual returns true.
         * Comparing canonical paths is definitive.
         */
        if ( pathNamesPossiblyEqual(this.url.getPath(), o.url.getPath()) ) {
            if ( getURLPath().equalsIgnoreCase(o.getURLPath()) ) {
                try {
                    return getAddress().equals(o.getAddress());
                }
                catch ( CIFSException uhe ) {
                    log.debug("Unknown host", uhe);
                    return getServer().equalsIgnoreCase(o.getServer());
                }
            }
        }
        return false;
    }


    private static boolean pathNamesPossiblyEqual ( String path1, String path2 ) {
        int p1, p2, l1, l2;

        // if unsure return this method returns true

        p1 = path1.lastIndexOf('/');
        p2 = path2.lastIndexOf('/');
        l1 = path1.length() - p1;
        l2 = path2.length() - p2;

        // anything with dots voids comparison
        if ( l1 > 1 && path1.charAt(p1 + 1) == '.' )
            return true;
        if ( l2 > 1 && path2.charAt(p2 + 1) == '.' )
            return true;

        return l1 == l2 && path1.regionMatches(true, p1, path2, p2, l1);
    }


    /**
     * 
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbResourceLocatorInternal#overlaps(jcifs.SmbResourceLocator)
     */
    @Override
    public boolean overlaps ( SmbResourceLocator other ) throws CIFSException {
        String tp = getCanonicalURL();
        String op = other.getCanonicalURL();
        return getAddress().equals(other.getAddress()) && tp.regionMatches(true, 0, op, 0, Math.min(tp.length(), op.length()));
    }


    /**
     * @param dr
     * @param reqPath
     * @return UNC path the redirect leads to
     */
    @Override
    public String handleDFSReferral ( DfsReferralData dr, String reqPath ) {
        if ( Objects.equals(this.dfsReferral, dr) ) {
            return this.unc;
        }
        this.dfsReferral = dr;

        String oldUncPath = getUNCPath();
        int pathConsumed = dr.getPathConsumed();
        if ( pathConsumed < 0 ) {
            log.warn("Path consumed out of range " + pathConsumed);
            pathConsumed = 0;
        }
        else if ( pathConsumed > this.unc.length() ) {
            log.warn("Path consumed out of range " + pathConsumed);
            pathConsumed = oldUncPath.length();
        }

        if ( log.isDebugEnabled() ) {
            log.debug("UNC is '" + oldUncPath + "'");
            log.debug("Consumed '" + oldUncPath.substring(0, pathConsumed) + "'");
        }
        String dunc = oldUncPath.substring(pathConsumed);
        if ( log.isDebugEnabled() ) {
            log.debug("Remaining '" + dunc + "'");
        }

        if ( dunc.equals("") || dunc.equals("\\") ) {
            dunc = "\\";
            this.type = SmbConstants.TYPE_SHARE;
        }
        if ( !dr.getPath().isEmpty() ) {
            dunc = "\\" + dr.getPath() + dunc;
        }

        if ( dunc.charAt(0) != '\\' ) {
            log.warn("No slash at start of remaining DFS path " + dunc);
        }

        this.unc = dunc;
        if ( dr.getShare() != null && !dr.getShare().isEmpty() ) {
            this.share = dr.getShare();
        }
        if ( reqPath != null && reqPath.endsWith("\\") && !dunc.endsWith("\\") ) {
            dunc += "\\";
        }
        return dunc;
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString () {
        StringBuilder sb = new StringBuilder(this.url.toString());
        sb.append('[');
        if ( this.unc != null ) {
            sb.append("unc=");
            sb.append(this.unc);
        }
        if ( this.canon != null ) {
            sb.append("canon=");
            sb.append(this.canon);
        }
        if ( this.dfsReferral != null ) {
            sb.append("dfsReferral=");
            sb.append(this.dfsReferral);
        }
        sb.append(']');
        return sb.toString();
    }

}
