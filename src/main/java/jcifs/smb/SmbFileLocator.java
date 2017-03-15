/**
 * © 2017 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 14.03.2017 by mbechler
 */
package jcifs.smb;


import java.net.URL;
import java.net.UnknownHostException;

import org.apache.log4j.Logger;

import jcifs.CIFSContext;
import jcifs.netbios.NbtAddress;
import jcifs.netbios.UniAddress;


/**
 * @author mbechler
 *
 */
public class SmbFileLocator {

    private static final Logger log = Logger.getLogger(SmbFileLocator.class);

    private final URL url;
    private String canon; // Initially null; set by getUncPath; dir must end with '/'
    private String share; // Can be null
    private DfsReferral dfsReferral = null; // For getDfsPath() and getServerWithDfs()

    private String unc; // Initially null; set by getUncPath; never ends with '/'
    private UniAddress[] addresses;
    private int addressIndex;
    private int type;

    private CIFSContext ctx;


    /**
     * 
     * @param ctx
     * @param u
     */
    public SmbFileLocator ( CIFSContext ctx, URL u ) {
        this.ctx = ctx;
        this.url = u;
    }


    /**
     * @param context
     * @param name
     */
    void setContext ( SmbFileLocator context, String name ) {
        if ( context.share != null ) {
            this.dfsReferral = context.dfsReferral;
        }
        int last = name.length() - 1;
        if ( last >= 0 && name.charAt(last) == '/' ) {
            name = name.substring(0, last);
        }

        context.canonicalizePath();
        if ( context.share == null ) {
            this.unc = "\\";
            this.canon = "/";
        }
        else if ( context.unc.equals("\\") ) {
            this.unc = '\\' + name;
            this.canon = '/' + name;
            this.share = context.share;
        }
        else {
            this.unc = context.unc + '\\' + name;
            this.canon = context.canon + '/' + name;
            this.share = context.share;
        }
    }


    /**
     * Returns the last component of the target URL. This will
     * effectively be the name of the file or directory represented by this
     * <code>SmbFile</code> or in the case of URLs that only specify a server
     * or workgroup, the server or workgroup will be returned. The name of
     * the root URL <code>smb://</code> is also <code>smb://</code>. If this
     * <tt>SmbFile</tt> refers to a workgroup, server, share, or directory,
     * the name will include a trailing slash '/' so that composing new
     * <tt>SmbFile</tt>s will maintain the trailing slash requirement.
     *
     * @return The last component of the URL associated with this SMB
     *         resource or <code>smb://</code> if the resource is <code>smb://</code>
     *         itself.
     */

    public String getName () {
        canonicalizePath();
        if ( this.canon.length() > 1 ) {
            int i = this.canon.length() - 2;
            while ( this.canon.charAt(i) != '/' ) {
                i--;
            }
            return this.canon.substring(i + 1);
        }
        else if ( this.share != null ) {
            return this.share + '/';
        }
        else if ( this.url.getHost().length() > 0 ) {
            return this.url.getHost() + '/';
        }
        else {
            return "smb://";
        }
    }


    /**
     * Everything but the last component of the URL representing this SMB
     * resource is effectivly it's parent. The root URL <code>smb://</code>
     * does not have a parent. In this case <code>smb://</code> is returned.
     *
     * @return The parent directory of this SMB resource or
     *         <code>smb://</code> if the resource refers to the root of the URL
     *         hierarchy which incedentally is also <code>smb://</code>.
     */
    public String getParent () {
        String str = this.url.getAuthority();

        if ( str.length() > 0 ) {
            StringBuffer sb = new StringBuffer("smb://");

            sb.append(str);

            canonicalizePath();
            if ( this.canon.length() > 1 ) {
                sb.append(this.canon);
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
     * Returns the full uncanonicalized URL of this SMB resource. An
     * <code>SmbFile</code> constructed with the result of this method will
     * result in an <code>SmbFile</code> that is equal to the original.
     *
     * @return The uncanonicalized full URL of this SMB resource.
     */

    public String getPath () {
        return this.url.toString();
    }


    /**
     * Retuns the Windows UNC style path with backslashs intead of forward slashes.
     *
     * @return The UNC path.
     */
    public String getCanonicalUncPath () {
        canonicalizePath();
        if ( this.share == null ) {
            return "\\\\" + this.url.getHost();
        }
        return "\\\\" + this.url.getHost() + this.canon.replace('/', '\\');
    }


    /**
     * 
     * @return possibly unresolved UNC path
     */
    public String getUncPath () {
        return this.unc;
    }


    /**
     * Returns the full URL of this SMB resource with '.' and '..' components
     * factored out. An <code>SmbFile</code> constructed with the result of
     * this method will result in an <code>SmbFile</code> that is equal to
     * the original.
     *
     * @return The canonicalized URL of this SMB resource.
     */

    public String getCanonicalPath () {
        String str = this.url.getAuthority();
        canonicalizePath();
        if ( str.length() > 0 ) {
            return "smb://" + this.url.getAuthority() + this.canon;
        }
        return "smb://";
    }


    /**
     * Retrieves the share associated with this SMB resource. In
     * the case of <code>smb://</code>, <code>smb://workgroup/</code>,
     * and <code>smb://server/</code> URLs which do not specify a share,
     * <code>null</code> will be returned.
     *
     * @return The share component or <code>null</code> if there is no share
     */

    public String getShare () {
        return this.share;
    }


    /**
     * Retrieve the hostname of the server for this SMB resource. If the resources has been resolved by DFS this will
     * return the target name.
     * 
     * @return The server name
     */
    public String getServerWithDfs () {
        if ( this.dfsReferral != null ) {
            return this.dfsReferral.server;
        }
        return getServer();
    }


    /**
     * Retrieve the hostname of the server for this SMB resource. If this
     * <code>SmbFile</code> references a workgroup, the name of the workgroup
     * is returned. If this <code>SmbFile</code> refers to the root of this
     * SMB network hierarchy, <code>null</code> is returned.
     * 
     * @return The server or workgroup name or <code>null</code> if this
     *         <code>SmbFile</code> refers to the root <code>smb://</code> resource.
     */
    public String getServer () {
        String str = this.url.getHost();
        if ( str.length() == 0 ) {
            return null;
        }
        return str;
    }


    /**
     * @return the transport port, if specified
     */
    public int getPort () {
        return this.url.getPort();
    }


    /**
     * @return the original URL
     */
    public URL getURL () {
        return this.url;
    }


    /**
     * If the path of this <code>SmbFile</code> falls within a DFS volume,
     * this method will return the referral path to which it maps. Otherwise
     * <code>null</code> is returned.
     * 
     * @return URL to the DFS volume
     * @throws SmbException
     */
    public String getDfsPath () throws SmbException {
        if ( this.dfsReferral == null ) {
            return null;
        }
        String path = "smb:/" + this.dfsReferral.server + "/" + this.dfsReferral.share + this.unc;
        return path.replace('\\', '/');
    }


    /**
     * @return whether to enforce the use of signing on connection to this resource
     */
    public boolean shouldForceSigning () {
        return this.ctx.getConfig().isIpcSigningEnforced() && !this.ctx.getCredentials().isAnonymous() && isIPC();
    }


    /**
     * @return whether this is a IPC
     */
    public boolean isIPC () {
        if ( log.isDebugEnabled() ) {
            log.debug("Check " + this.share);
        }
        if ( this.share == null || "IPC$".equals(this.share) ) {
            if ( log.isDebugEnabled() ) {
                log.debug("Share is " + this.share + " enforcing signing");
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
     * Returns type of of object this <tt>SmbFile</tt> represents.
     * 
     * @return <tt>TYPE_FILESYSTEM, TYPE_WORKGROUP, TYPE_SERVER,
     * TYPE_NAMED_PIPE</tt>, or <tt>TYPE_SHARE</tt> in which case it may be either <tt>TYPE_SHARE</tt>,
     *         <tt>TYPE_PRINTER</tt> or <tt>TYPE_COMM</tt>.
     * @throws SmbException
     */
    public int getType () throws SmbException {
        if ( this.type == 0 ) {
            if ( canonicalizePath().length() > 1 ) {
                this.type = SmbFile.TYPE_FILESYSTEM;
            }
            else if ( this.share != null ) {
                if ( this.share.equals("IPC$") ) {
                    this.type = SmbFile.TYPE_NAMED_PIPE;
                }
                else {
                    this.type = SmbFile.TYPE_SHARE;
                }
            }
            else if ( this.url.getAuthority() == null || this.url.getAuthority().length() == 0 ) {
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
     * @return whether this is a workgroup reference
     * @throws UnknownHostException
     */
    public boolean isWorkgroup () throws UnknownHostException {
        if ( this.type == SmbFile.TYPE_WORKGROUP || this.url.getHost().length() == 0 ) {
            this.type = SmbFile.TYPE_WORKGROUP;
            return true;
        }

        canonicalizePath();
        if ( this.share == null ) {
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


    UniAddress getAddress () throws UnknownHostException {
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

        String host = this.url.getHost();
        String path = this.url.getPath();
        String query = this.url.getQuery();

        if ( query != null ) {
            String server = queryLookup(query, "server");
            if ( server != null && server.length() > 0 ) {
                this.addresses = new UniAddress[1];
                this.addresses[ 0 ] = this.ctx.getNameServiceClient().getByName(server);
                return getNextAddress();
            }
            String address = queryLookup(query, "address");
            if ( address != null && address.length() > 0 ) {
                byte[] ip = java.net.InetAddress.getByName(address).getAddress();
                this.addresses = new UniAddress[1];
                this.addresses[ 0 ] = new UniAddress(java.net.InetAddress.getByAddress(host, ip));
                return getNextAddress();
            }
        }

        if ( host.length() == 0 ) {
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
     * 
     * @return whether this is a root resource
     */
    public boolean isRoot () {
        // length == 0 should not happen
        return canonicalizePath().length() <= 1;
    }


    String canonicalizePath () {
        if ( this.unc == null ) {
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
                        return null;
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
                    this.unc = this.canon.substring(i, out[ o ] == '/' ? o : o + 1);
                    this.unc = this.unc.replace('/', '\\');
                }
            }
            else {
                this.share = null;
                this.unc = "\\";
            }
        }
        return this.unc;
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
        canonicalizePath();
        return hash + this.canon.toUpperCase().hashCode();
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals ( Object obj ) {
        if ( ! ( obj instanceof SmbFileLocator ) ) {
            return false;
        }

        SmbFileLocator o = (SmbFileLocator) obj;

        /*
         * If uncertain, pathNamesPossiblyEqual returns true.
         * Comparing canonical paths is definitive.
         */
        if ( pathNamesPossiblyEqual(this.url.getPath(), o.url.getPath()) ) {

            this.canonicalizePath();
            o.canonicalizePath();

            if ( this.canon.equalsIgnoreCase(o.canon) ) {
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
     * @param other
     * @return whether the paths share a common root
     * @throws UnknownHostException
     */
    public boolean overlaps ( SmbFileLocator other ) throws UnknownHostException {
        return getAddress().equals(other.getAddress())
                && this.canon.regionMatches(true, 0, other.canon, 0, Math.min(this.canon.length(), other.canon.length()));
    }


    /**
     * @param dr
     * @param reqPath
     * @return UNC path the redirect leads to
     */
    public String handleDFSReferral ( DfsReferral dr, String reqPath ) {
        this.dfsReferral = dr;
        if ( dr.pathConsumed < 0 ) {
            log.warn("Path consumed out of range " + dr.pathConsumed);
            dr.pathConsumed = 0;
        }
        else if ( dr.pathConsumed > this.unc.length() ) {
            log.warn("Path consumed out of range " + dr.pathConsumed);
            dr.pathConsumed = this.unc.length();
        }

        if ( log.isDebugEnabled() ) {
            log.debug("UNC is '" + this.unc + "'");
            log.debug("Consumed '" + this.unc.substring(0, dr.pathConsumed) + "'");
        }
        String dunc = this.unc.substring(dr.pathConsumed);
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
        if ( reqPath != null && reqPath.endsWith("\\") && !dunc.endsWith("\\") ) {
            dunc += "\\";
        }

        return dunc;
    }

}
