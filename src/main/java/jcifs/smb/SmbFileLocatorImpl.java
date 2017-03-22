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


import java.net.URL;
import java.net.UnknownHostException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
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
 * @author mbechler
 *
 */
class SmbFileLocatorImpl implements SmbFileLocator, Cloneable {

    private static final Logger log = LoggerFactory.getLogger(SmbFileLocatorImpl.class);

    private final URL url;

    private DfsReferral dfsReferral = null; // For getDfsPath() and getServerWithDfs()

    private String unc; // Initially null; set by getUncPath; never ends with '/'
    private String canon; // Initially null; set by getUncPath; dir must end with '/'
    private String share; // Can be null

    private UniAddress[] addresses;
    private int addressIndex;
    private int type;

    private CIFSContext ctx;


    /**
     * 
     * @param ctx
     * @param u
     */
    public SmbFileLocatorImpl ( CIFSContext ctx, URL u ) {
        this.ctx = ctx;
        this.url = u;
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#clone()
     */
    @Override
    protected SmbFileLocatorImpl clone () {
        SmbFileLocatorImpl loc = new SmbFileLocatorImpl(this.ctx, this.url);
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
    void resolveInContext ( SmbFileLocatorImpl context, String name ) {
        if ( context.share != null ) {
            this.dfsReferral = context.dfsReferral;
        }
        int last = name.length() - 1;
        if ( last >= 0 && name.charAt(last) == '/' ) {
            name = name.substring(0, last);
        }

        if ( context.getShare() == null ) {
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
                this.unc = "\\" + String.join("\\", remainParts);
                this.canon = "/" + this.share + "/" + String.join("/", remainParts);
            }
            else {
                this.unc = "\\";
                if ( this.share != null ) {
                    this.canon = "/" + this.share;
                }
                else {
                    this.canon = "/";
                }
            }
        }
        else if ( context.getUNCPath().equals("\\") ) {
            // context share != null, so the remainder is path
            this.unc = '\\' + name.replace('/', '\\');
            this.canon = context.getURLPath() + name;
            this.share = context.getShare();
        }
        else {
            this.unc = context.getUNCPath() + '\\' + name.replace('/', '\\');
            this.canon = context.getURLPath() + '/' + name;
            this.share = context.getShare();
        }
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbFileLocator#getName()
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
     * @see jcifs.smb.SmbFileLocator#getParent()
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
     * @see jcifs.smb.SmbFileLocator#getPath()
     */

    @Override
    public String getPath () {
        return this.url.toString();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbFileLocator#getCanonicalURL()
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
     * @see jcifs.smb.SmbFileLocator#getServerWithDfs()
     */
    @Override
    public String getServerWithDfs () {
        if ( this.dfsReferral != null ) {
            return this.dfsReferral.server;
        }
        return getServer();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbFileLocator#getServer()
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
     * @see jcifs.smb.SmbFileLocator#getDfsPath()
     */
    @Override
    public String getDfsPath () {
        if ( this.dfsReferral == null ) {
            return null;
        }
        return "smb:/" + this.dfsReferral.server + "/" + this.dfsReferral.share + this.getUNCPath().replace('\\', '/');
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbFileLocator#getPort()
     */
    @Override
    public int getPort () {
        return this.url.getPort();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbFileLocator#getURL()
     */
    @Override
    public URL getURL () {
        return this.url;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbFileLocator#shouldForceSigning()
     */
    @Override
    public boolean shouldForceSigning () {
        return this.ctx.getConfig().isIpcSigningEnforced() && !this.ctx.getCredentials().isAnonymous() && isIPC();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbFileLocator#isIPC()
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
     * @see jcifs.smb.SmbFileLocator#getType()
     */
    @Override
    public int getType () throws SmbException {
        if ( this.type == 0 ) {
            if ( getUNCPath().length() > 1 ) {
                this.type = SmbFile.TYPE_FILESYSTEM;
            }
            else if ( getShare() != null ) {
                if ( getShare().equals("IPC$") ) {
                    this.type = SmbFile.TYPE_NAMED_PIPE;
                }
                else {
                    this.type = SmbFile.TYPE_SHARE;
                }
            }
            else if ( this.url.getAuthority() == null || this.url.getAuthority().isEmpty() ) {
                this.type = SmbFile.TYPE_WORKGROUP;
            }
            else {
                UniAddress addr;
                try {
                    addr = getAddress();
                }
                catch ( UnknownHostException uhe ) {
                    throw new SmbException(this.url.toString(), uhe);
                }
                if ( addr.getAddress() instanceof NbtAddress ) {
                    int code = ( (NbtAddress) addr.getAddress() ).getNameType();
                    if ( code == 0x1d || code == 0x1b ) {
                        this.type = SmbFile.TYPE_WORKGROUP;
                        return this.type;
                    }
                }
                this.type = SmbFile.TYPE_SERVER;
            }
        }
        return this.type;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbFileLocator#isWorkgroup()
     */
    @Override
    public boolean isWorkgroup () throws UnknownHostException {
        if ( this.type == SmbFile.TYPE_WORKGROUP || this.url.getHost().length() == 0 ) {
            this.type = SmbFile.TYPE_WORKGROUP;
            return true;
        }

        if ( getShare() == null ) {
            UniAddress addr = getAddress();
            if ( addr.getAddress() instanceof NbtAddress ) {
                int code = ( (NbtAddress) addr.getAddress() ).getNameType();
                if ( code == 0x1d || code == 0x1b ) {
                    this.type = SmbFile.TYPE_WORKGROUP;
                    return true;
                }
            }
            this.type = SmbFile.TYPE_SERVER;
        }
        return false;
    }


    @Override
    public UniAddress getAddress () throws UnknownHostException {
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


    UniAddress getFirstAddress () throws UnknownHostException {
        this.addressIndex = 0;

        if ( this.addresses == null ) {
            String host = this.url.getHost();
            String path = this.url.getPath();
            String query = this.url.getQuery();

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
                    NbtAddress addr = this.ctx.getNameServiceClient().getNbtByName(NbtAddress.MASTER_BROWSER_NAME, 0x01, null);
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

        return getNextAddress();
    }


    UniAddress getNextAddress () {
        UniAddress addr = null;
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
     * @see jcifs.smb.SmbFileLocator#isRoot()
     */
    @Override
    public boolean isRoot () {
        // length == 0 should not happen
        return getShare() == null && getUNCPath().length() <= 1;
    }


    /**
     * 
     */
    private synchronized void canonicalizePath () {
        char[] in = this.url.getPath().toCharArray();
        char[] out = new char[in.length];
        int length = in.length, i, o, state;

        /*
         * The canonicalization routine
         */
        state = 0;
        o = 0;
        for ( i = 0; i < length; i++ ) {
            switch ( state ) {
            case 0:
                if ( in[ i ] != '/' ) {
                    return;
                }
                out[ o++ ] = in[ i ];
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
                    if ( o == 1 )
                        break;
                    do {
                        o--;
                    }
                    while ( o > 1 && out[ o - 1 ] != '/' );
                    break;
                }
                state = 2;
            case 2:
                if ( in[ i ] == '/' ) {
                    state = 1;
                }
                out[ o++ ] = in[ i ];
                break;
            }
        }

        this.canon = new String(out, 0, o);
        if ( o > 1 ) {
            o--;
            i = this.canon.indexOf('/', 1);
            if ( i < 0 ) {
                this.share = this.canon.substring(1);
                this.unc = "\\";
            }
            else if ( i == o ) {
                this.share = this.canon.substring(1, i);
                this.unc = "\\";
            }
            else {
                this.share = this.canon.substring(1, i);
                this.unc = this.canon.substring(i, out[ o ] == '/' ? o : o + 1).replace('/', '\\');
            }
        }
        else {
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
        catch ( UnknownHostException uhe ) {
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
        if ( ! ( obj instanceof SmbFileLocatorImpl ) ) {
            return false;
        }

        SmbFileLocatorImpl o = (SmbFileLocatorImpl) obj;

        /*
         * If uncertain, pathNamesPossiblyEqual returns true.
         * Comparing canonical paths is definitive.
         */
        if ( pathNamesPossiblyEqual(this.url.getPath(), o.url.getPath()) ) {
            if ( getURLPath().equalsIgnoreCase(o.getURLPath()) ) {
                try {
                    return getAddress().equals(o.getAddress());
                }
                catch ( UnknownHostException uhe ) {
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
     * @see jcifs.smb.SmbFileLocator#overlaps(jcifs.smb.SmbFileLocator)
     */
    @Override
    public boolean overlaps ( SmbFileLocator other ) throws UnknownHostException {
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
    public String handleDFSReferral ( DfsReferral dr, String reqPath ) {
        this.dfsReferral = dr;

        String oldUncPath = getUNCPath();
        if ( dr.pathConsumed < 0 ) {
            log.warn("Path consumed out of range " + dr.pathConsumed);
            dr.pathConsumed = 0;
        }
        else if ( dr.pathConsumed > this.unc.length() ) {
            log.warn("Path consumed out of range " + dr.pathConsumed);
            dr.pathConsumed = oldUncPath.length();
        }

        if ( log.isDebugEnabled() ) {
            log.debug("UNC is '" + oldUncPath + "'");
            log.debug("Consumed '" + oldUncPath.substring(0, dr.pathConsumed) + "'");
        }
        String dunc = oldUncPath.substring(dr.pathConsumed);
        if ( log.isDebugEnabled() ) {
            log.debug("Remaining '" + dunc + "'");
        }

        if ( dunc.equals("") )
            dunc = "\\";
        if ( !dr.path.equals("") )
            dunc = "\\" + dr.path + dunc;

        if ( dunc.charAt(0) != '\\' ) {
            log.warn("No slash at start of remaining DFS path " + dunc);
        }

        this.unc = dunc;
        if ( dr.share != null && !dr.share.isEmpty() ) {
            this.share = dr.share;
        }
        if ( reqPath != null && reqPath.endsWith("\\") && !dunc.endsWith("\\") ) {
            dunc += "\\";
        }
        return dunc;
    }

}
