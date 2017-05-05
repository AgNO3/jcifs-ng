/* jcifs smb client library in Java
 * Copyright (C) 2000  "Michael B. Allen" <jcifs at samba dot org>
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
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownHostException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.CloseableIterator;
import jcifs.Configuration;
import jcifs.ResourceFilter;
import jcifs.ResourceNameFilter;
import jcifs.SmbConstants;
import jcifs.SmbFileHandle;
import jcifs.SmbResource;
import jcifs.SmbResourceLocator;
import jcifs.SmbTreeHandle;
import jcifs.SmbWatchHandle;
import jcifs.context.SingletonContext;
import jcifs.dcerpc.DcerpcHandle;
import jcifs.dcerpc.msrpc.MsrpcShareGetInfo;


/**
 * This class represents a resource on an SMB network. Mainly these
 * resources are files and directories however an <code>SmbFile</code>
 * may also refer to servers and workgroups. If the resource is a file or
 * directory the methods of <code>SmbFile</code> follow the behavior of
 * the well known {@link java.io.File} class. One fundamental difference
 * is the usage of a URL scheme [1] to specify the target file or
 * directory. SmbFile URLs have the following syntax:
 *
 * <blockquote>
 * 
 * <pre>
 *     smb://[[[domain;]username[:password]@]server[:port]/[[share/[dir/]file]]][?param=value[param2=value2[...]]]
 * </pre>
 * 
 * </blockquote>
 *
 * This example:
 *
 * <blockquote>
 * 
 * <pre>
 *     smb://storage15/public/foo.txt
 * </pre>
 * 
 * </blockquote>
 *
 * would reference the file <code>foo.txt</code> in the share
 * <code>public</code> on the server <code>storage15</code>. In addition
 * to referencing files and directories, jCIFS can also address servers,
 * and workgroups.
 * <p>
 * <font color="#800000"><i>Important: all SMB URLs that represent
 * workgroups, servers, shares, or directories require a trailing slash '/'.
 * </i></font>
 * <p>
 * When using the <tt>java.net.URL</tt> class with
 * 'smb://' URLs it is necessary to first call the static
 * <tt>jcifs.Config.registerSmbURLHandler();</tt> method. This is required
 * to register the SMB protocol handler.
 * <p>
 * The userinfo component of the SMB URL (<tt>domain;user:pass</tt>) must
 * be URL encoded if it contains reserved characters. According to RFC 2396
 * these characters are non US-ASCII characters and most meta characters
 * however jCIFS will work correctly with anything but '@' which is used
 * to delimit the userinfo component from the server and '%' which is the
 * URL escape character itself.
 * <p>
 * The server
 * component may a traditional NetBIOS name, a DNS name, or IP
 * address. These name resolution mechanisms and their resolution order
 * can be changed (See <a href="../../../resolver.html">Setting Name
 * Resolution Properties</a>). The servername and path components are
 * not case sensitive but the domain, username, and password components
 * are. It is also likely that properties must be specified for jcifs
 * to function (See <a href="../../overview-summary.html#scp">Setting
 * JCIFS Properties</a>). Here are some examples of SMB URLs with brief
 * descriptions of what they do:
 *
 * <p>
 * [1] This URL scheme is based largely on the <i>SMB
 * Filesharing URL Scheme</i> IETF draft.
 * 
 * <p>
 * <table border="1" cellpadding="3" cellspacing="0" width="100%" summary="URL examples">
 * <tr bgcolor="#ccccff">
 * <td colspan="2"><b>SMB URL Examples</b></td>
 * <tr>
 * <td width="20%"><b>URL</b></td>
 * <td><b>Description</b></td>
 * </tr>
 * 
 * <tr>
 * <td width="20%"><code>smb://users-nyc;miallen:mypass@angus/tmp/</code></td>
 * <td>
 * This URL references a share called <code>tmp</code> on the server
 * <code>angus</code> as user <code>miallen</code> who's password is
 * <code>mypass</code>.
 * </td>
 * </tr>
 * 
 * <tr>
 * <td width="20%">
 * <code>smb://Administrator:P%40ss@msmith1/c/WINDOWS/Desktop/foo.txt</code></td>
 * <td>
 * A relativly sophisticated example that references a file
 * <code>msmith1</code>'s desktop as user <code>Administrator</code>. Notice the '@' is URL encoded with the '%40'
 * hexcode escape.
 * </td>
 * </tr>
 * 
 * <tr>
 * <td width="20%"><code>smb://angus/</code></td>
 * <td>
 * This references only a server. The behavior of some methods is different
 * in this context(e.g. you cannot <code>delete</code> a server) however
 * as you might expect the <code>list</code> method will list the available
 * shares on this server.
 * </td>
 * </tr>
 * 
 * <tr>
 * <td width="20%"><code>smb://myworkgroup/</code></td>
 * <td>
 * This syntactically is identical to the above example. However if
 * <code>myworkgroup</code> happends to be a workgroup(which is indeed
 * suggested by the name) the <code>list</code> method will return
 * a list of servers that have registered themselves as members of
 * <code>myworkgroup</code>.
 * </td>
 * </tr>
 * 
 * <tr>
 * <td width="20%"><code>smb://</code></td>
 * <td>
 * Just as <code>smb://server/</code> lists shares and
 * <code>smb://workgroup/</code> lists servers, the <code>smb://</code>
 * URL lists all available workgroups on a netbios LAN. Again,
 * in this context many methods are not valid and return default
 * values(e.g. <code>isHidden</code> will always return false).
 * </td>
 * </tr>
 * 
 * <tr>
 * <td width="20%"><code>smb://angus.foo.net/d/jcifs/pipes.doc</code></td>
 * <td>
 * The server name may also be a DNS name as it is in this example. See
 * <a href="../../../resolver.html">Setting Name Resolution Properties</a>
 * for details.
 * </td>
 * </tr>
 * 
 * <tr>
 * <td width="20%"><code>smb://192.168.1.15/ADMIN$/</code></td>
 * <td>
 * The server name may also be an IP address. See <a
 * href="../../../resolver.html">Setting Name Resolution Properties</a>
 * for details.
 * </td>
 * </tr>
 * 
 * <tr>
 * <td width="20%">
 * <code>smb://domain;username:password@server/share/path/to/file.txt</code></td>
 * <td>
 * A prototypical example that uses all the fields.
 * </td>
 * </tr>
 * 
 * <tr>
 * <td width="20%"><code>smb://myworkgroup/angus/ &lt;-- ILLEGAL </code></td>
 * <td>
 * Despite the hierarchial relationship between workgroups, servers, and
 * filesystems this example is not valid.
 * </td>
 * </tr>
 *
 * <tr>
 * <td width="20%">
 * <code>smb://server/share/path/to/dir &lt;-- ILLEGAL </code></td>
 * <td>
 * URLs that represent workgroups, servers, shares, or directories require a trailing slash '/'.
 * </td>
 * </tr>
 *
 * <tr>
 * <td width="20%">
 * <code>smb://MYGROUP/?SERVER=192.168.10.15</code></td>
 * <td>
 * SMB URLs support some query string parameters. In this example
 * the <code>SERVER</code> parameter is used to override the
 * server name service lookup to contact the server 192.168.10.15
 * (presumably known to be a master
 * browser) for the server list in workgroup <code>MYGROUP</code>.
 * </td>
 * </tr>
 *
 * </table>
 * 
 * <p>
 * A second constructor argument may be specified to augment the URL
 * for better programmatic control when processing many files under
 * a common base. This is slightly different from the corresponding
 * <code>java.io.File</code> usage; a '/' at the beginning of the second
 * parameter will still use the server component of the first parameter. The
 * examples below illustrate the resulting URLs when this second contructor
 * argument is used.
 *
 * <p>
 * <table border="1" cellpadding="3" cellspacing="0" width="100%" summary="Usage examples">
 * <tr bgcolor="#ccccff">
 * <td colspan="3">
 * <b>Examples Of SMB URLs When Augmented With A Second Constructor Parameter</b></td>
 * <tr>
 * <td width="20%">
 * <b>First Parameter</b></td>
 * <td><b>Second Parameter</b></td>
 * <td><b>Result</b></td>
 * </tr>
 *
 * <tr>
 * <td width="20%"><code>
 *  smb://host/share/a/b/
 * </code></td>
 * <td width="20%"><code>
 *  c/d/
 * </code></td>
 * <td><code>
 *  smb://host/share/a/b/c/d/
 * </code></td>
 * </tr>
 * 
 * <tr>
 * <td width="20%"><code>
 *  smb://host/share/foo/bar/
 * </code></td>
 * <td width="20%"><code>
 *  /share2/zig/zag
 * </code></td>
 * <td><code>
 *  smb://host/share2/zig/zag
 * </code></td>
 * </tr>
 * 
 * <tr>
 * <td width="20%"><code>
 *  smb://host/share/foo/bar/
 * </code></td>
 * <td width="20%"><code>
 *  ../zip/
 * </code></td>
 * <td><code>
 *  smb://host/share/foo/zip/
 * </code></td>
 * </tr>
 * 
 * <tr>
 * <td width="20%"><code>
 *  smb://host/share/zig/zag
 * </code></td>
 * <td width="20%"><code>
 *  smb://foo/bar/
 * </code></td>
 * <td><code>
 *  smb://foo/bar/
 * </code></td>
 * </tr>
 * 
 * <tr>
 * <td width="20%"><code>
 *  smb://host/share/foo/
 * </code></td>
 * <td width="20%"><code>
 *  ../.././.././../foo/
 * </code></td>
 * <td><code>
 *  smb://host/foo/
 * </code></td>
 * </tr>
 * 
 * <tr>
 * <td width="20%"><code>
 *  smb://host/share/zig/zag
 * </code></td>
 * <td width="20%"><code>
 *  /
 * </code></td>
 * <td><code>
 *  smb://host/
 * </code></td>
 * </tr>
 * 
 * <tr>
 * <td width="20%"><code>
 *  smb://server/
 * </code></td>
 * <td width="20%"><code>
 *  ../
 * </code></td>
 * <td><code>
 *  smb://server/
 * </code></td>
 * </tr>
 * 
 * <tr>
 * <td width="20%"><code>
 *  smb://
 * </code></td>
 * <td width="20%"><code>
 *  myworkgroup/
 * </code></td>
 * <td><code>
 *  smb://myworkgroup/
 * </code></td>
 * </tr>
 * 
 * <tr>
 * <td width="20%"><code>
 *  smb://myworkgroup/
 * </code></td>
 * <td width="20%"><code>
 *  angus/
 * </code></td>
 * <td><code>
 *  smb://myworkgroup/angus/ &lt;-- ILLEGAL<br>(But if you first create an <tt>SmbFile</tt> with 'smb://workgroup/' and
 * use and use it as the first parameter to a constructor that accepts it with a second <tt>String</tt> parameter jCIFS
 * will factor out the 'workgroup'.)
 * </code></td>
 * </tr>
 * 
 * </table>
 *
 * <p>
 * Instances of the <code>SmbFile</code> class are immutable; that is,
 * once created, the abstract pathname represented by an SmbFile object
 * will never change.
 *
 * @see java.io.File
 */

public class SmbFile extends URLConnection implements SmbResource, SmbConstants {

    protected static final int ATTR_GET_MASK = 0x7FFF;
    protected static final int ATTR_SET_MASK = 0x30A7;
    protected static final int DEFAULT_ATTR_EXPIRATION_PERIOD = 5000;

    protected static final int HASH_DOT = ".".hashCode();
    protected static final int HASH_DOT_DOT = "..".hashCode();

    private static Logger log = LoggerFactory.getLogger(SmbFile.class);

    private long createTime;
    private long lastModified;
    private long lastAccess;
    private int attributes;
    private long attrExpiration;
    private long size;
    private long sizeExpiration;
    private boolean isExists;

    private CIFSContext transportContext;
    private SmbTreeConnection treeConnection;
    protected final SmbResourceLocatorImpl fileLocator;
    private SmbTreeHandleImpl treeHandle;


    /**
     * Constructs an SmbFile representing a resource on an SMB network such as
     * a file or directory. See the description and examples of smb URLs above.
     *
     * @param url
     *            A URL string
     * @throws MalformedURLException
     *             If the <code>parent</code> and <code>child</code> parameters
     *             do not follow the prescribed syntax
     */
    @Deprecated
    public SmbFile ( String url ) throws MalformedURLException {
        this(new URL(null, url, SingletonContext.getInstance().getUrlHandler()));
    }


    /**
     * Constructs an SmbFile representing a resource on an SMB network such
     * as a file or directory from a <tt>URL</tt> object.
     *
     * @param url
     *            The URL of the target resource
     */
    @Deprecated
    public SmbFile ( URL url ) {
        this(url, SingletonContext.getInstance().withCredentials(new NtlmPasswordAuthentication(SingletonContext.getInstance(), url.getUserInfo())));
    }


    /**
     * Constructs an SmbFile representing a resource on an SMB network such
     * as a file or directory. The second parameter is a relative path from
     * the <code>parent SmbFile</code>. See the description above for examples
     * of using the second <code>name</code> parameter.
     *
     * @param context
     *            A base <code>SmbFile</code>
     * @param name
     *            A path string relative to the <code>parent</code> paremeter
     * @throws MalformedURLException
     *             If the <code>parent</code> and <code>child</code> parameters
     *             do not follow the prescribed syntax
     * @throws UnknownHostException
     *             If the server or workgroup of the <tt>context</tt> file cannot be determined
     */
    public SmbFile ( SmbResource context, String name ) throws MalformedURLException, UnknownHostException {
        this(
            isWorkgroup(context) ? new URL(null, "smb://" + checkName(name), context.getContext().getUrlHandler())
                    : new URL(context.getLocator().getURL(), checkName(name), context.getContext().getUrlHandler()),
            context.getContext());
        setContext(context, name);
    }


    /**
     * Construct from string URL
     * 
     * @param url
     * @param tc
     *            context to use
     * @throws MalformedURLException
     */
    public SmbFile ( String url, CIFSContext tc ) throws MalformedURLException {
        this(new URL(null, url, tc.getUrlHandler()), tc);
    }


    /**
     * Construct from URL
     * 
     * @param url
     * @param tc
     *            context to use
     */
    public SmbFile ( URL url, CIFSContext tc ) {
        super(url);
        this.transportContext = tc;
        this.fileLocator = new SmbResourceLocatorImpl(tc, url);
        this.treeConnection = new SmbTreeConnection(tc);
    }


    SmbFile ( SmbResource context, String name, boolean loadedAttributes, int type, int attributes, long createTime, long lastModified,
            long lastAccess, long size ) throws MalformedURLException {
        this(
            isWorkgroup(context) ? new URL(null, "smb://" + checkName(name) + "/", Handler.SMB_HANDLER)
                    : new URL(context.getLocator().getURL(), checkName(name) + ( ( attributes & ATTR_DIRECTORY ) > 0 ? "/" : "" )),
            context.getContext());

        setContext(context, name);

        /*
         * why? am I going around in circles?
         * this.type = type == TYPE_WORKGROUP ? 0 : type;
         */
        this.fileLocator.updateType(type);
        this.attributes = attributes;
        this.createTime = createTime;
        this.lastModified = lastModified;
        this.lastAccess = lastAccess;
        this.size = size;
        this.isExists = true;

        if ( loadedAttributes ) {
            this.attrExpiration = this.sizeExpiration = System.currentTimeMillis() + getContext().getConfig().getAttributeCacheTimeout();
        }
    }


    /**
     * @return
     */
    private static boolean isWorkgroup ( SmbResource r ) {
        try {
            return r.getLocator().isWorkgroup();
        }
        catch ( CIFSException e ) {
            log.debug("Failed to check for workgroup", e);
            return false;
        }
    }


    /**
     * {@inheritDoc}
     *
     * @see java.net.URLConnection#connect()
     */
    @Override
    public void connect () throws IOException {
        try ( SmbTreeHandle th = ensureTreeConnected() ) {}
    }


    /**
     * 
     * @return a tree handle
     * @throws SmbException
     */
    public SmbTreeHandle getTreeHandle () throws SmbException {
        return ensureTreeConnected();
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.AutoCloseable#close()
     */
    @Override
    public synchronized void close () {
        SmbTreeHandleImpl th = this.treeHandle;
        if ( th != null ) {
            this.treeHandle = null;
            if ( this.transportContext.getConfig().isStrictResourceLifecycle() ) {
                th.close();
            }
        }
    }


    /**
     * @return
     * @throws SmbException
     * 
     */
    synchronized SmbTreeHandleImpl ensureTreeConnected () throws SmbException {
        if ( this.treeHandle == null ) {
            this.treeHandle = this.treeConnection.connectWrapException(this.fileLocator);
            if ( this.transportContext.getConfig().isStrictResourceLifecycle() ) {
                // one extra share to keep the tree alive
                return this.treeHandle.acquire();
            }
            return this.treeHandle;
        }
        return this.treeHandle.acquire();
    }


    /**
     * @param context
     * @param name
     */
    private void setContext ( SmbResource context, String name ) {
        this.fileLocator.resolveInContext(context.getLocator(), name);
        if ( context.getLocator().getShare() != null && ( context instanceof SmbFile ) ) {
            this.treeConnection = new SmbTreeConnection( ( (SmbFile) context ).treeConnection);
        }
        else {
            this.treeConnection = new SmbTreeConnection(context.getContext());
        }
    }


    private static String checkName ( String name ) throws MalformedURLException {
        if ( name == null || name.length() == 0 ) {
            throw new MalformedURLException("Name must not be empty");
        }
        return name;
    }


    /**
     * @param nonPooled
     *            whether this file will use an exclusive connection
     */
    protected void setNonPooled ( boolean nonPooled ) {
        this.treeConnection.setNonPooled(nonPooled);
    }


    /**
     * @return the transportContext
     */
    @Deprecated
    public CIFSContext getTransportContext () {
        return this.getContext();
    }


    @Override
    public CIFSContext getContext () {
        return this.transportContext;
    }


    @Override
    public SmbResourceLocator getLocator () {
        return this.fileLocator;
    }


    @Override
    public SmbResource resolve ( String name ) throws CIFSException {
        try {
            if ( name == null || name.length() == 0 ) {
                throw new SmbException("Name must not be empty");
            }
            return new SmbFile(this, name);
        }
        catch (
            MalformedURLException |
            UnknownHostException e ) {
            // this should not actually happen
            throw new SmbException("Failed to resolve child element", e);
        }
    }


    SmbFileHandleImpl openUnshared ( int flags, int access, int sharing, int attrs, int options ) throws CIFSException {
        return openUnshared(getUncPath(), flags, access, sharing, attrs, options);
    }


    SmbFileHandleImpl openUnshared ( String uncPath, int flags, int access, int sharing, int attrs, int options ) throws CIFSException {
        SmbFileHandleImpl fh = null;
        try ( SmbTreeHandleImpl h = ensureTreeConnected() ) {

            if ( log.isDebugEnabled() ) {
                log.debug(String.format("openUnshared: %s flags: %x access: %x attrs: %x options: %x", uncPath, flags, access, attrs, options));
            }

            /*
             * NT Create AndX / Open AndX Request / Response
             */
            Configuration config = h.getConfig();
            if ( h.hasCapability(SmbConstants.CAP_NT_SMBS) ) {
                SmbComNTCreateAndXResponse response = new SmbComNTCreateAndXResponse(config);
                SmbComNTCreateAndX request = new SmbComNTCreateAndX(config, uncPath, flags, access, sharing, attrs, options, null);
                customizeCreate(request, response);

                h.send(request, response);

                this.fileLocator.updateType(response.fileType);
                this.createTime = response.creationTime;
                this.lastModified = response.lastWriteTime;
                this.lastAccess = response.lastAccessTime;
                this.size = response.allocationSize;
                this.attributes = response.extFileAttributes & ATTR_GET_MASK;
                this.attrExpiration = System.currentTimeMillis() + config.getAttributeCacheTimeout();
                this.isExists = true;
                fh = new SmbFileHandleImpl(config, response.fid, h, uncPath, flags, access, attrs, options);
            }
            else {
                SmbComOpenAndXResponse response = new SmbComOpenAndXResponse(config);
                h.send(new SmbComOpenAndX(config, uncPath, access, sharing, flags, null), response);
                this.fileLocator.updateType(response.fileType);
                this.lastModified = response.lastWriteTime + h.getServerTimeZoneOffset();
                this.size = response.dataSize;
                this.attributes = response.fileAttributes & ATTR_GET_MASK;
                this.attrExpiration = System.currentTimeMillis() + config.getAttributeCacheTimeout();
                this.isExists = true;
                fh = new SmbFileHandleImpl(config, response.fid, h, uncPath, flags, access, 0, 0);
            }
            return fh;
        }
    }


    /**
     * @return this file's unc path below the share
     */
    public String getUncPath () {
        return this.fileLocator.getUNCPath();
    }


    /**
     * @param request
     * @param response
     */
    protected void customizeCreate ( SmbComNTCreateAndX request, SmbComNTCreateAndXResponse response ) {}


    Info queryPath ( String path, int infoLevel ) throws CIFSException {
        try ( SmbTreeHandleImpl th = ensureTreeConnected() ) {

            if ( log.isDebugEnabled() ) {
                log.debug("queryPath: " + path);
            }

            /*
             * We really should do the referral before this in case
             * the redirected target has different capabilities. But
             * the way we have been doing that is to call exists() which
             * calls this method so another technique will be necessary
             * to support DFS referral _to_ Win95/98/ME.
             */

            if ( th.hasCapability(SmbConstants.CAP_NT_SMBS) ) {
                /*
                 * Trans2 Query Path Information Request / Response
                 */
                Trans2QueryPathInformationResponse response = new Trans2QueryPathInformationResponse(th.getConfig(), infoLevel);
                th.send(new Trans2QueryPathInformation(th.getConfig(), path, infoLevel), response);

                if ( log.isDebugEnabled() ) {
                    log.debug("Path information " + response);
                }
                return response.info;
            }

            /*
             * Query Information Request / Response
             */
            SmbComQueryInformationResponse response = new SmbComQueryInformationResponse(th.getConfig(), th.getServerTimeZoneOffset());
            th.send(new SmbComQueryInformation(th.getConfig(), path), response);
            if ( log.isDebugEnabled() ) {
                log.debug("Legacy path information " + response);
            }
            return response;
        }
    }


    @Override
    public boolean exists () throws SmbException {

        if ( this.attrExpiration > System.currentTimeMillis() ) {
            log.trace("Using cached attributes");
            return this.isExists;
        }

        this.attributes = ATTR_READONLY | ATTR_DIRECTORY;
        this.createTime = 0L;
        this.lastModified = 0L;
        this.lastAccess = 0L;
        this.isExists = false;

        try {
            if ( this.url.getHost().length() == 0 ) {}
            else if ( this.fileLocator.getShare() == null ) {
                if ( this.fileLocator.getType() == TYPE_WORKGROUP ) {
                    getContext().getNameServiceClient().getByName(this.url.getHost(), true);
                }
                else {
                    getContext().getNameServiceClient().getByName(this.url.getHost()).getHostName();
                }
            }
            else if ( this.fileLocator.isRoot() || this.fileLocator.isIPC() ) {
                // treeConnect is good enough
                try ( SmbTreeHandle th = this.ensureTreeConnected() ) {}
            }
            else {
                Info info = queryPath(this.fileLocator.getUNCPath(), Trans2QueryPathInformationResponse.SMB_QUERY_FILE_BASIC_INFO);
                this.attributes = info.getAttributes();
                this.createTime = info.getCreateTime();
                this.lastModified = info.getLastWriteTime();
                this.lastAccess = info.getLastAccessTime();
            }

            /*
             * If any of the above fail, isExists will not be set true
             */

            this.isExists = true;

        }
        catch ( UnknownHostException uhe ) {
            log.debug("Unknown host", uhe);
        }
        catch ( SmbException se ) {
            log.trace("exists:", se);
            switch ( se.getNtStatus() ) {
            case NtStatus.NT_STATUS_NO_SUCH_FILE:
            case NtStatus.NT_STATUS_OBJECT_NAME_INVALID:
            case NtStatus.NT_STATUS_OBJECT_NAME_NOT_FOUND:
            case NtStatus.NT_STATUS_OBJECT_PATH_NOT_FOUND:
                break;
            default:
                throw se;
            }
        }
        catch ( CIFSException e ) {
            throw SmbException.wrap(e);
        }

        this.attrExpiration = System.currentTimeMillis() + getContext().getConfig().getAttributeCacheTimeout();
        return this.isExists;
    }


    @Override
    public int getType () throws SmbException {
        try {
            int t = this.fileLocator.getType();
            if ( t == TYPE_SHARE ) {
                try ( SmbTreeHandle th = ensureTreeConnected() ) {
                    if ( th.getConnectedService().equals("LPT1:") ) {
                        t = TYPE_PRINTER;
                        this.fileLocator.updateType(t);
                    }
                    else if ( th.getConnectedService().equals("COMM") ) {
                        t = TYPE_COMM;
                        this.fileLocator.updateType(t);
                    }
                }
            }
            return t;
        }
        catch ( CIFSException e ) {
            throw SmbException.wrap(e);
        }
    }


    @Override
    public String getName () {
        return this.fileLocator.getName();
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
        return this.fileLocator.getParent();
    }


    /**
     * Returns the full uncanonicalized URL of this SMB resource. An
     * <code>SmbFile</code> constructed with the result of this method will
     * result in an <code>SmbFile</code> that is equal to the original.
     *
     * @return The uncanonicalized full URL of this SMB resource.
     */

    public String getPath () {
        return this.fileLocator.getPath();
    }


    /**
     * Retuns the Windows UNC style path with backslashs intead of forward slashes.
     *
     * @return The UNC path.
     */
    public String getCanonicalUncPath () {
        return this.fileLocator.getCanonicalURL();
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
        try {
            String path = this.treeConnection.ensureDFSResolved(this.fileLocator).getDfsPath();
            if ( isDirectory() ) {
                path += '/';
            }
            return path;
        }
        catch ( CIFSException e ) {
            throw SmbException.wrap(e);
        }
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
        return this.fileLocator.getCanonicalURL();
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
        return this.fileLocator.getShare();
    }


    /**
     * Retrieve the hostname of the server for this SMB resource. If the resources has been resolved by DFS this will
     * return the target name.
     * 
     * @return The server name
     */
    public String getServerWithDfs () {
        return this.fileLocator.getServerWithDfs();
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
        return this.fileLocator.getServer();
    }


    @Override
    public SmbWatchHandle watch ( int filter, boolean recursive ) throws CIFSException {

        if ( filter == 0 ) {
            throw new IllegalArgumentException("filter must not be 0");
        }

        if ( !isDirectory() ) {
            throw new SmbException("Is not a directory");
        }

        try ( SmbTreeHandleImpl th = ensureTreeConnected() ) {
            if ( !th.hasCapability(SmbConstants.CAP_NT_SMBS) ) {
                throw new SmbUnsupportedOperationException("Not supported without CAP_NT_SMBS");
            }
            return new SmbWatchHandleImpl(openUnshared(O_RDONLY, READ_CONTROL, DEFAULT_SHARING, 0, 1), filter, recursive);
        }
    }


    @Override
    public boolean canRead () throws SmbException {
        if ( getType() == TYPE_NAMED_PIPE ) { // try opening the pipe for reading?
            return true;
        }
        return exists(); // try opening and catch sharing violation?
    }


    @Override
    public boolean canWrite () throws SmbException {
        if ( getType() == TYPE_NAMED_PIPE ) { // try opening the pipe for writing?
            return true;
        }
        return exists() && ( this.attributes & ATTR_READONLY ) == 0;
    }


    @Override
    public boolean isDirectory () throws SmbException {
        if ( this.fileLocator.isRoot() ) {
            return true;
        }
        if ( !exists() )
            return false;
        return ( this.attributes & ATTR_DIRECTORY ) == ATTR_DIRECTORY;
    }


    @Override
    public boolean isFile () throws SmbException {
        if ( this.fileLocator.isRoot() ) {
            return false;
        }
        exists();
        return ( this.attributes & ATTR_DIRECTORY ) == 0;
    }


    @Override
    public boolean isHidden () throws SmbException {
        if ( this.fileLocator.getShare() == null ) {
            return false;
        }
        else if ( this.fileLocator.isRoot() ) {
            if ( this.fileLocator.getShare().endsWith("$") ) {
                return true;
            }
            return false;
        }
        exists();
        return ( this.attributes & ATTR_HIDDEN ) == ATTR_HIDDEN;
    }


    @Override
    public long createTime () throws SmbException {
        if ( !this.fileLocator.isRoot() ) {
            exists();
            return this.createTime;
        }
        return 0L;
    }


    @Override
    public long lastModified () throws SmbException {
        if ( !this.fileLocator.isRoot() ) {
            exists();
            return this.lastModified;
        }
        return 0L;
    }


    @Override
    public long lastAccess () throws SmbException {
        if ( !this.fileLocator.isRoot() ) {
            exists();
            return this.lastAccess;
        }
        return 0L;
    }


    /**
     * List the contents of this SMB resource. The list returned by this
     * method will be;
     *
     * <ul>
     * <li>files and directories contained within this resource if the
     * resource is a normal disk file directory,
     * <li>all available NetBIOS workgroups or domains if this resource is
     * the top level URL <code>smb://</code>,
     * <li>all servers registered as members of a NetBIOS workgroup if this
     * resource refers to a workgroup in a <code>smb://workgroup/</code> URL,
     * <li>all browseable shares of a server including printers, IPC
     * services, or disk volumes if this resource is a server URL in the form
     * <code>smb://server/</code>,
     * <li>or <code>null</code> if the resource cannot be resolved.
     * </ul>
     *
     * @return A <code>String[]</code> array of files and directories,
     *         workgroups, servers, or shares depending on the context of the
     *         resource URL
     * @throws SmbException
     */
    public String[] list () throws SmbException {
        return SmbEnumerationUtil.list(this, "*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, null, null);
    }


    /**
     * List the contents of this SMB resource. The list returned will be
     * identical to the list returned by the parameterless <code>list()</code>
     * method minus filenames filtered by the specified filter.
     *
     * @param filter
     *            a filename filter to exclude filenames from the results
     * @return <code>String[]</code> array of matching files and directories,
     *         workgroups, servers, or shares depending on the context of the
     *         resource URL
     * @throws SmbException
     *             # @return An array of filenames
     */
    public String[] list ( SmbFilenameFilter filter ) throws SmbException {
        return SmbEnumerationUtil.list(this, "*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, filter, null);
    }


    /**
     * List the contents of this SMB resource as an array of
     * <code>SmbResource</code> objects. This method is much more efficient than
     * the regular <code>list</code> method when querying attributes of each
     * file in the result set.
     * <p>
     * The list of <code>SmbResource</code>s returned by this method will be;
     *
     * <ul>
     * <li>files and directories contained within this resource if the
     * resource is a normal disk file directory,
     * <li>all available NetBIOS workgroups or domains if this resource is
     * the top level URL <code>smb://</code>,
     * <li>all servers registered as members of a NetBIOS workgroup if this
     * resource refers to a workgroup in a <code>smb://workgroup/</code> URL,
     * <li>all browseable shares of a server including printers, IPC
     * services, or disk volumes if this resource is a server URL in the form
     * <code>smb://server/</code>,
     * <li>or <code>null</code> if the resource cannot be resolved.
     * </ul>
     * 
     * If strict resource lifecycle is used, make sure you close the individual files after use.
     *
     * @return An array of <code>SmbResource</code> objects representing file
     *         and directories, workgroups, servers, or shares depending on the context
     *         of the resource URL
     * @throws SmbException
     */
    public SmbFile[] listFiles () throws SmbException {
        return SmbEnumerationUtil.listFiles(this, "*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, null, null);
    }


    /**
     * The CIFS protocol provides for DOS "wildcards" to be used as
     * a performance enhancement. The client does not have to filter
     * the names and the server does not have to return all directory
     * entries.
     * <p>
     * The wildcard expression may consist of two special meta
     * characters in addition to the normal filename characters. The '*'
     * character matches any number of characters in part of a name. If
     * the expression begins with one or more '?'s then exactly that
     * many characters will be matched whereas if it ends with '?'s
     * it will match that many characters <i>or less</i>.
     * <p>
     * Wildcard expressions will not filter workgroup names or server names.
     *
     * <blockquote>
     * 
     * <pre>
     * winnt&gt; ls c?o*
     * clock.avi                  -rw--      82944 Mon Oct 14 1996 1:38 AM
     * Cookies                    drw--          0 Fri Nov 13 1998 9:42 PM
     * 2 items in 5ms
     * </pre>
     * 
     * </blockquote>
     * 
     * If strict resource lifecycle is used, make sure you close the individual files after use.
     *
     * @param wildcard
     *            a wildcard expression
     * @throws SmbException
     * @return An array of <code>SmbResource</code> objects representing file
     *         and directories, workgroups, servers, or shares depending on the context
     *         of the resource URL
     */
    public SmbFile[] listFiles ( String wildcard ) throws SmbException {
        return SmbEnumerationUtil.listFiles(this, wildcard, ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, null, null);
    }


    /**
     * List the contents of this SMB resource. The list returned will be
     * identical to the list returned by the parameterless <code>listFiles()</code>
     * method minus files filtered by the specified filename filter.
     * 
     * If strict resource lifecycle is used, make sure you close the individual files after use.
     *
     * @param filter
     *            a filter to exclude files from the results
     * @return An array of <tt>SmbResource</tt> objects
     * @throws SmbException
     */
    public SmbFile[] listFiles ( SmbFilenameFilter filter ) throws SmbException {
        return SmbEnumerationUtil.listFiles(this, "*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, filter, null);
    }


    /**
     * List the contents of this SMB resource. The list returned will be
     * identical to the list returned by the parameterless <code>listFiles()</code>
     * method minus filenames filtered by the specified filter.
     * 
     * If strict resource lifecycle is used, make sure you close the individual files after use.
     *
     * @param filter
     *            a file filter to exclude files from the results
     * @return An array of <tt>SmbResource</tt> objects
     * @throws SmbException
     */
    public SmbFile[] listFiles ( SmbFileFilter filter ) throws SmbException {
        return SmbEnumerationUtil.listFiles(this, "*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, null, filter);
    }


    @Override
    public CloseableIterator<SmbResource> children () throws CIFSException {
        return SmbEnumerationUtil.doEnum(this, "*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, null, null);
    }


    @Override
    public CloseableIterator<SmbResource> children ( String wildcard ) throws CIFSException {
        return SmbEnumerationUtil.doEnum(this, wildcard, ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, null, null);
    }


    @Override
    public CloseableIterator<SmbResource> children ( ResourceNameFilter filter ) throws CIFSException {
        return SmbEnumerationUtil.doEnum(this, "*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, filter, null);
    }


    @Override
    public CloseableIterator<SmbResource> children ( ResourceFilter filter ) throws CIFSException {
        return SmbEnumerationUtil.doEnum(this, "*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, null, filter);
    }


    @Override
    public void renameTo ( SmbResource d ) throws SmbException {
        if ( ! ( d instanceof SmbFile ) ) {
            throw new SmbException("Invalid target resource");
        }
        SmbFile dest = (SmbFile) d;
        try ( SmbTreeHandleImpl sh = ensureTreeConnected();
              SmbTreeHandleImpl th = dest.ensureTreeConnected() ) {
            sh.ensureDFSResolved();
            th.ensureDFSResolved();

            if ( this.fileLocator.isRoot() || dest.getLocator().isRoot() ) {
                throw new SmbException("Invalid operation for workgroups, servers, or shares");
            }

            if ( !sh.isSameTree(th) ) {
                // trigger requests to resolve the actual target
                exists();
                dest.exists();
                if ( !sh.isSameTree(th) ) {
                    throw new SmbException("Cannot rename between different trees");
                }
            }

            if ( log.isDebugEnabled() ) {
                log.debug("renameTo: " + getUncPath() + " -> " + dest.getUncPath());
            }

            this.attrExpiration = this.sizeExpiration = 0;
            dest.attrExpiration = 0;

            /*
             * Rename Request / Response
             */
            sh.send(new SmbComRename(sh.getConfig(), getUncPath(), dest.getUncPath()), new SmbComBlankResponse(sh.getConfig()));
        }
        catch ( CIFSException e ) {
            throw SmbException.wrap(e);
        }
    }


    void copyRecursive ( SmbFile dest, byte[][] b, int bsize, WriterThread w, SmbTreeHandleImpl sh, SmbTreeHandleImpl dh ) throws CIFSException {
        if ( this.attrExpiration < System.currentTimeMillis() ) {
            this.attributes = ATTR_READONLY | ATTR_DIRECTORY;
            this.createTime = 0L;
            this.lastModified = 0L;
            this.isExists = false;

            Info info = queryPath(this.fileLocator.getUNCPath(), Trans2QueryPathInformationResponse.SMB_QUERY_FILE_BASIC_INFO);
            this.attributes = info.getAttributes();
            this.createTime = info.getCreateTime();
            this.lastModified = info.getLastWriteTime();

            /*
             * If any of the above fails, isExists will not be set true
             */

            this.isExists = true;
            this.attrExpiration = System.currentTimeMillis() + getContext().getConfig().getAttributeCacheTimeout();
        }

        if ( isDirectory() ) {
            SmbCopyUtil.copyDir(this, dest, b, bsize, w, sh, dh);
        }
        else {
            SmbCopyUtil.copyFile(this, dest, b, bsize, w, sh, dh);
        }
    }


    @Override
    public void copyTo ( SmbResource d ) throws SmbException {
        if ( ! ( d instanceof SmbFile ) ) {
            throw new SmbException("Invalid target resource");
        }
        SmbFile dest = (SmbFile) d;
        try ( SmbTreeHandleImpl sh = ensureTreeConnected();
              SmbTreeHandleImpl dh = dest.ensureTreeConnected() ) {

            sh.ensureDFSResolved();
            dh.ensureDFSResolved();

            /*
             * Should be able to copy an entire share actually
             */
            if ( this.fileLocator.getShare() == null || dest.getLocator().getShare() == null ) {
                throw new SmbException("Invalid operation for workgroups or servers");
            }

            /*
             * At this point the maxBufferSize values are from the server
             * exporting the volumes, not the one that we will actually
             * end up performing IO with. If the server hosting the
             * actual files has a smaller maxBufSize this could be
             * incorrect. To handle this properly it is necessary
             * to redirect the tree to the target server first before
             * establishing buffer size. These exists() calls facilitate
             * that.
             */
            // exists();
            // dest.exists();
            sh.ensureDFSResolved();
            dh.ensureDFSResolved();

            /*
             * It is invalid for the source path to be a child of the destination
             * path or visa versa.
             */
            if ( this.fileLocator.overlaps(dest.getLocator()) ) {
                throw new SmbException("Source and destination paths overlap.");
            }

            WriterThread w = new WriterThread();
            w.setDaemon(true);

            try {
                w.start();
                // use commonly acceptable buffer size
                int bsize = Math.min(sh.getReceiveBufferSize() - 70, dh.getSendBufferSize() - 70);
                byte[][] b = new byte[2][bsize];
                copyRecursive(dest, b, bsize, w, sh, dh);
            }
            finally {
                w.write(null, -1, null);
                w.interrupt();
                try {
                    w.join();
                }
                catch ( InterruptedException e ) {
                    log.warn("Interrupted while joining copy thread", e);
                }
            }
        }
        catch ( CIFSException e ) {
            throw SmbException.wrap(e);
        }
    }


    @Override
    public void delete () throws SmbException {
        exists();
        try {
            delete(this.fileLocator.getUNCPath());
        }
        catch ( CIFSException e ) {
            throw SmbException.wrap(e);
        }
        close();
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#finalize()
     */
    @Override
    protected void finalize () throws Throwable {
        if ( this.treeHandle != null ) {
            log.debug("File was not properly released " + this);
        }
    }


    void delete ( String fileName ) throws CIFSException {
        if ( this.fileLocator.isRoot() ) {
            throw new SmbException("Invalid operation for workgroups, servers, or shares");
        }

        try ( SmbTreeHandleImpl th = ensureTreeConnected() ) {
            if ( System.currentTimeMillis() > this.attrExpiration ) {
                this.attributes = ATTR_READONLY | ATTR_DIRECTORY;
                this.createTime = 0L;
                this.lastModified = 0L;
                this.lastAccess = 0L;
                this.isExists = false;

                Info info = queryPath(this.fileLocator.getUNCPath(), Trans2QueryPathInformationResponse.SMB_QUERY_FILE_BASIC_INFO);
                this.attributes = info.getAttributes();
                this.createTime = info.getCreateTime();
                this.lastModified = info.getLastWriteTime();
                this.lastAccess = info.getLastAccessTime();

                this.attrExpiration = System.currentTimeMillis() + getContext().getConfig().getAttributeCacheTimeout();
                this.isExists = true;
            }

            if ( ( this.attributes & ATTR_READONLY ) != 0 ) {
                setReadWrite();
            }

            /*
             * Delete or Delete Directory Request / Response
             */

            if ( log.isDebugEnabled() ) {
                log.debug("delete: " + fileName);
            }

            if ( ( this.attributes & ATTR_DIRECTORY ) != 0 ) {

                /*
                 * Recursively delete directory contents
                 */

                try ( CloseableIterator<SmbResource> it = SmbEnumerationUtil
                        .doEnum(this, "*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, null, null) ) {
                    while ( it.hasNext() ) {
                        try ( SmbResource r = it.next() ) {
                            try {
                                r.delete();
                            }
                            catch ( CIFSException e ) {
                                throw SmbException.wrap(e);
                            }
                        }
                    }
                }
                catch ( SmbException se ) {
                    /*
                     * Oracle FilesOnline version 9.0.4 doesn't send '.' and '..' so
                     * listFiles may generate undesireable "cannot find
                     * the file specified".
                     */
                    log.debug("delete", se);
                    if ( se.getNtStatus() != NtStatus.NT_STATUS_NO_SUCH_FILE ) {
                        throw se;
                    }
                }
                th.send(new SmbComDeleteDirectory(th.getConfig(), fileName), new SmbComBlankResponse(th.getConfig()));
            }
            else {
                th.send(new SmbComDelete(th.getConfig(), fileName), new SmbComBlankResponse(th.getConfig()));
            }
            this.attrExpiration = this.sizeExpiration = 0;
        }
    }


    @Override
    public long length () throws SmbException {
        if ( this.sizeExpiration > System.currentTimeMillis() ) {
            return this.size;
        }

        try {
            int t = getType();
            if ( t == TYPE_SHARE ) {
                try ( SmbTreeHandleImpl th = ensureTreeConnected() ) {
                    int level = Trans2QueryFSInformationResponse.SMB_INFO_ALLOCATION;
                    Trans2QueryFSInformationResponse response = new Trans2QueryFSInformationResponse(th.getConfig(), level);
                    th.send(new Trans2QueryFSInformation(th.getConfig(), level), response);

                    this.size = response.info.getCapacity();
                }
            }
            else if ( !this.fileLocator.isRoot() && t != TYPE_NAMED_PIPE ) {
                Info info = queryPath(this.fileLocator.getUNCPath(), Trans2QueryPathInformationResponse.SMB_QUERY_FILE_STANDARD_INFO);
                this.size = info.getSize();
            }
            else {
                this.size = 0L;
            }
            this.sizeExpiration = System.currentTimeMillis() + getContext().getConfig().getAttributeCacheTimeout();
            return this.size;
        }
        catch ( CIFSException e ) {
            throw SmbException.wrap(e);
        }
    }


    @Override
    public long getDiskFreeSpace () throws SmbException {
        try {
            int t = getType();
            if ( t == TYPE_SHARE || t == TYPE_FILESYSTEM ) {
                int level = Trans2QueryFSInformationResponse.SMB_FS_FULL_SIZE_INFORMATION;
                try {
                    return queryFSInformation(level);
                }
                catch ( SmbException ex ) {
                    log.debug("getDiskFreeSpace", ex);
                    switch ( ex.getNtStatus() ) {
                    case NtStatus.NT_STATUS_INVALID_INFO_CLASS:
                    case NtStatus.NT_STATUS_UNSUCCESSFUL: // NetApp Filer
                        // SMB_FS_FULL_SIZE_INFORMATION not supported by the server.
                        level = Trans2QueryFSInformationResponse.SMB_INFO_ALLOCATION;
                        return queryFSInformation(level);
                    }
                    throw ex;
                }
            }
            return 0L;
        }
        catch ( CIFSException e ) {
            throw SmbException.wrap(e);
        }
    }


    private long queryFSInformation ( int level ) throws CIFSException {
        try ( SmbTreeHandleImpl th = ensureTreeConnected() ) {
            Trans2QueryFSInformationResponse response = new Trans2QueryFSInformationResponse(th.getConfig(), level);
            th.send(new Trans2QueryFSInformation(th.getConfig(), level), response);

            if ( getType() == TYPE_SHARE ) {
                this.size = response.info.getCapacity();
                this.sizeExpiration = System.currentTimeMillis() + getContext().getConfig().getAttributeCacheTimeout();
            }

            return response.info.getFree();
        }
    }


    @Override
    public void mkdir () throws SmbException {
        String path = this.fileLocator.getUNCPath();

        if ( path.length() == 1 ) {
            throw new SmbException("Invalid operation for workgroups, servers, or shares");
        }

        try ( SmbTreeHandleImpl th = ensureTreeConnected() ) {
            exists();
            th.ensureDFSResolved();

            // get the path again, this may have changed through DFS referrals
            path = this.fileLocator.getUNCPath();

            /*
             * Create Directory Request / Response
             */

            if ( log.isDebugEnabled() ) {
                log.debug("mkdir: " + path);
            }

            th.send(new SmbComCreateDirectory(th.getConfig(), path), new SmbComBlankResponse(th.getConfig()));
            this.attrExpiration = this.sizeExpiration = 0;
        }
        catch ( CIFSException e ) {
            throw SmbException.wrap(e);
        }
    }


    @Override
    public void mkdirs () throws SmbException {
        String p = this.fileLocator.getParent();
        try ( SmbTreeHandle th = ensureTreeConnected();
              SmbFile parent = new SmbFile(p, getContext()) ) {
            try {
                if ( !parent.exists() ) {
                    if ( log.isDebugEnabled() ) {
                        log.debug("Parent does not exist " + p);
                    }
                    parent.mkdirs();
                }
            }
            catch ( SmbException e ) {
                if ( log.isDebugEnabled() ) {
                    log.debug("Failed to ensure parent exists " + p, e);
                }
                throw e;
            }
            try {
                mkdir();
            }
            catch ( SmbException e ) {
                log.debug("mkdirs", e);
                // Ignore "Cannot create a file when that file already exists." errors for now as
                // they seem to be show up under some cinditions most likely due to timing issues.
                if ( e.getNtStatus() != NtStatus.NT_STATUS_OBJECT_NAME_COLLISION ) {
                    throw e;
                }
            }
        }
        catch ( CIFSException e ) {
            throw SmbException.wrap(e);
        }
        catch ( MalformedURLException e ) {
            throw new SmbException("Invalid URL in mkdirs", e);
        }
    }


    @Override
    public void createNewFile () throws SmbException {
        if ( this.fileLocator.isRoot() ) {
            throw new SmbException("Invalid operation for workgroups, servers, or shares");
        }

        try ( SmbFileHandle fd = openUnshared(O_RDWR | O_CREAT | O_EXCL, FILE_NO_SHARE, 0, ATTR_NORMAL, 0) ) {
            // close explicitly
            fd.close(0L);
        }
        catch ( CIFSException e ) {
            throw SmbException.wrap(e);
        }
    }


    void setPathInformation ( int attrs, long ctime, long mtime, long atime ) throws CIFSException {
        try ( SmbTreeHandleImpl th = ensureTreeConnected() ) {
            exists();
            if ( !th.hasCapability(SmbConstants.CAP_NT_SMBS) ) {
                if ( ctime != 0 || atime != 0 ) {
                    throw new SmbUnsupportedOperationException("Cannot set creation or access time without CAP_NT_SMBS");
                }
                th.send(
                    new SmbComSetInformation(th.getConfig(), getUncPath(), attrs, mtime - th.getServerTimeZoneOffset()),
                    new SmbComSetInformationResponse(th.getConfig()));
            }
            else {
                int dir = this.attributes & ATTR_DIRECTORY;
                try ( SmbFileHandleImpl f = openUnshared(
                    O_RDONLY,
                    FILE_WRITE_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    dir,
                    dir != 0 ? 0x0001 : 0x0040) ) {
                    th.send(
                        new Trans2SetFileInformation(th.getConfig(), f.getFid(), attrs | dir, ctime, mtime, atime),
                        new Trans2SetFileInformationResponse(th.getConfig()),
                        RequestParam.NO_RETRY);
                }
            }
            this.attrExpiration = 0;
        }
    }


    @Override
    public void setCreateTime ( long time ) throws SmbException {
        if ( this.fileLocator.isRoot() ) {
            throw new SmbException("Invalid operation for workgroups, servers, or shares");
        }

        try {
            setPathInformation(0, time, 0L, 0L);
        }
        catch ( CIFSException e ) {
            throw SmbException.wrap(e);
        }
    }


    @Override
    public void setLastModified ( long time ) throws SmbException {
        if ( this.fileLocator.isRoot() ) {
            throw new SmbException("Invalid operation for workgroups, servers, or shares");
        }

        try {
            setPathInformation(0, 0L, time, 0L);
        }
        catch ( CIFSException e ) {
            throw SmbException.wrap(e);
        }
    }


    @Override
    public void setLastAccess ( long time ) throws SmbException {
        if ( this.fileLocator.isRoot() ) {
            throw new SmbException("Invalid operation for workgroups, servers, or shares");
        }

        try {
            setPathInformation(0, 0L, 0L, time);
        }
        catch ( CIFSException e ) {
            throw SmbException.wrap(e);
        }
    }


    @Override
    public int getAttributes () throws SmbException {
        if ( this.fileLocator.isRoot() ) {
            return 0;
        }
        exists();
        return this.attributes & ATTR_GET_MASK;
    }


    @Override
    public void setAttributes ( int attrs ) throws SmbException {
        if ( this.fileLocator.isRoot() ) {
            throw new SmbException("Invalid operation for workgroups, servers, or shares");
        }
        try {
            setPathInformation(attrs & ATTR_SET_MASK, 0L, 0L, 0L);
        }
        catch ( CIFSException e ) {
            throw SmbException.wrap(e);
        }
    }


    @Override
    public void setReadOnly () throws SmbException {
        setAttributes(getAttributes() | ATTR_READONLY);
    }


    @Override
    public void setReadWrite () throws SmbException {
        setAttributes(getAttributes() & ~ATTR_READONLY);
    }


    /**
     * Returns a {@link java.net.URL} for this <code>SmbFile</code>. The
     * <code>URL</code> may be used as any other <code>URL</code> might to
     * access an SMB resource. Currently only retrieving data and information
     * is supported (i.e. no <tt>doOutput</tt>).
     *
     * @deprecated Use getURL() instead
     * @return A new <code>{@link java.net.URL}</code> for this <code>SmbFile</code>
     */
    @Deprecated
    public URL toURL () {
        return getURL();
    }


    /**
     * Computes a hashCode for this file based on the URL string and IP
     * address if the server. The hashing function uses the hashcode of the
     * server address, the canonical representation of the URL, and does not
     * compare authentication information. In essance, two
     * <code>SmbFile</code> objects that refer to
     * the same file should generate the same hashcode provided it is possible
     * to make such a determination.
     *
     * @return A hashcode for this abstract file
     */
    @Override
    public int hashCode () {
        return this.fileLocator.hashCode();
    }


    /**
     * Tests to see if two <code>SmbFile</code> objects are equal. Two
     * SmbFile objects are equal when they reference the same SMB
     * resource. More specifically, two <code>SmbFile</code> objects are
     * equals if their server IP addresses are equal and the canonicalized
     * representation of their URLs, minus authentication parameters, are
     * case insensitivly and lexographically equal.
     * <br>
     * For example, assuming the server <code>angus</code> resolves to the
     * <code>192.168.1.15</code> IP address, the below URLs would result in
     * <code>SmbFile</code>s that are equal.
     *
     * <p>
     * <blockquote>
     * 
     * <pre>
     * smb://192.168.1.15/share/DIR/foo.txt
     * smb://angus/share/data/../dir/foo.txt
     * </pre>
     * 
     * </blockquote>
     *
     * @param obj
     *            Another <code>SmbFile</code> object to compare for equality
     * @return <code>true</code> if the two objects refer to the same SMB resource
     *         and <code>false</code> otherwise
     */

    @Override
    public boolean equals ( Object obj ) {
        if ( obj instanceof SmbFile ) {
            SmbResource f = (SmbResource) obj;

            if ( this == f )
                return true;

            return this.fileLocator.equals(f.getLocator());
        }

        return false;
    }


    /**
     * Returns the string representation of this SmbFile object. This will
     * be the same as the URL used to construct this <code>SmbFile</code>.
     * This method will return the same value
     * as <code>getPath</code>.
     *
     * @return The original URL representation of this SMB resource
     */

    @Override
    public String toString () {
        return this.url.toString();
    }


    /* URLConnection implementation */
    /**
     * This URLConnection method just returns the result of <tt>length()</tt>.
     *
     * @return the length of this file or 0 if it refers to a directory
     */
    @Deprecated
    @Override
    public int getContentLength () {
        try {
            return (int) ( length() & 0xFFFFFFFFL );
        }
        catch ( SmbException se ) {
            log.debug("getContentLength", se);
        }
        return 0;
    }


    /**
     * {@inheritDoc}
     *
     * @see java.net.URLConnection#getContentLengthLong()
     */
    @Override
    public long getContentLengthLong () {
        try {
            return length();
        }
        catch ( SmbException se ) {
            log.debug("getContentLength", se);
        }
        return 0;
    }


    /**
     * This URLConnection method just returns the result of <tt>lastModified</tt>.
     *
     * @return the last modified data as milliseconds since Jan 1, 1970
     */
    @Override
    public long getDate () {
        try {
            return lastModified();
        }
        catch ( SmbException se ) {
            log.debug("getDate", se);
        }
        return 0L;
    }


    /**
     * This URLConnection method just returns the result of <tt>lastModified</tt>.
     *
     * @return the last modified data as milliseconds since Jan 1, 1970
     */
    @Override
    public long getLastModified () {
        try {
            return lastModified();
        }
        catch ( SmbException se ) {
            log.debug("getLastModified", se);
        }
        return 0L;
    }


    /**
     * This URLConnection method just returns a new <tt>SmbFileInputStream</tt> created with this file.
     *
     * @throws IOException
     *             thrown by <tt>SmbFileInputStream</tt> constructor
     */
    @Override
    public InputStream getInputStream () throws IOException {
        return new SmbFileInputStream(this);
    }


    @Override
    public SmbFileInputStream openInputStream () throws SmbException {
        return new SmbFileInputStream(this);
    }


    @Override
    public SmbFileInputStream openInputStream ( int sharing ) throws SmbException {
        return openInputStream(0, O_RDONLY, sharing);
    }


    @Override
    public SmbFileInputStream openInputStream ( int flags, int access, int sharing ) throws SmbException {
        return new SmbFileInputStream(this, flags, access, sharing, false);
    }


    @Override
    public OutputStream getOutputStream () throws IOException {
        return new SmbFileOutputStream(this);
    }


    @Override
    public SmbFileOutputStream openOutputStream () throws SmbException {
        return new SmbFileOutputStream(this);
    }


    @Override
    public SmbFileOutputStream openOutputStream ( boolean append ) throws SmbException {
        return openOutputStream(append, FILE_SHARE_READ);
    }


    @Override
    public SmbFileOutputStream openOutputStream ( boolean append, int sharing ) throws SmbException {
        return openOutputStream(append, append ? O_CREAT | O_WRONLY | O_APPEND : O_CREAT | O_WRONLY | O_TRUNC, 0, sharing);
    }


    @Override
    public SmbFileOutputStream openOutputStream ( boolean append, int openFlags, int access, int sharing ) throws SmbException {
        return new SmbFileOutputStream(this, append, openFlags, access, sharing);
    }


    @Override
    public SmbRandomAccessFile openRandomAccess ( String mode ) throws SmbException {
        return new SmbRandomAccessFile(this, mode);
    }


    @Override
    public SmbRandomAccessFile openRandomAccess ( String mode, int sharing ) throws SmbException {
        return new SmbRandomAccessFile(this, mode, sharing, false);
    }


    private void processAces ( ACE[] aces, boolean resolveSids ) throws IOException {
        String server = this.fileLocator.getServerWithDfs();
        int ai;

        if ( resolveSids ) {
            SID[] sids = new SID[aces.length];
            for ( ai = 0; ai < aces.length; ai++ ) {
                sids[ ai ] = aces[ ai ].sid;
            }

            for ( int off = 0; off < sids.length; off += 64 ) {
                int len = sids.length - off;
                if ( len > 64 )
                    len = 64;

                getContext().getSIDResolver().resolveSids(getContext(), server, sids, off, len);
            }
        }
        else {
            for ( ai = 0; ai < aces.length; ai++ ) {
                aces[ ai ].sid.origin_server = server;
                aces[ ai ].sid.origin_ctx = getContext();
            }
        }
    }


    @Override
    public long fileIndex () throws SmbException {
        return 0;
    }


    @Override
    public ACE[] getSecurity () throws IOException {
        return getSecurity(false);
    }


    @Override
    public ACE[] getSecurity ( boolean resolveSids ) throws IOException {
        try ( SmbTreeHandleImpl th = ensureTreeConnected() ) {
            if ( !th.hasCapability(SmbConstants.CAP_NT_SMBS) ) {
                throw new SmbUnsupportedOperationException("Not supported without CAP_NT_SMBS");
            }

            ACE[] aces;

            NtTransQuerySecurityDescResponse response = new NtTransQuerySecurityDescResponse(th.getConfig());
            try ( SmbFileHandleImpl f = openUnshared(O_RDONLY, READ_CONTROL, DEFAULT_SHARING, 0, isDirectory() ? 1 : 0) ) {
                /*
                 * NtTrans Query Security Desc Request / Response
                 */

                NtTransQuerySecurityDesc request = new NtTransQuerySecurityDesc(th.getConfig(), f.getFid(), 0x04);
                th.send(request, response, RequestParam.NO_RETRY);
            }

            aces = response.securityDescriptor.aces;
            if ( aces != null )
                processAces(aces, resolveSids);

            return aces;
        }
    }


    @Override
    public SID getOwnerUser () throws IOException {
        return getOwnerUser(true);
    }


    @Override
    public SID getOwnerUser ( boolean resolve ) throws IOException {
        try ( SmbTreeHandleImpl th = ensureTreeConnected() ) {
            if ( !th.hasCapability(SmbConstants.CAP_NT_SMBS) ) {
                throw new SmbUnsupportedOperationException("Not supported without CAP_NT_SMBS");
            }
            NtTransQuerySecurityDescResponse response = new NtTransQuerySecurityDescResponse(getContext().getConfig());

            try ( SmbFileHandleImpl f = openUnshared(O_RDONLY, READ_CONTROL, DEFAULT_SHARING, 0, isDirectory() ? 1 : 0) ) {
                /*
                 * NtTrans Query Security Desc Request / Response
                 */
                NtTransQuerySecurityDesc request = new NtTransQuerySecurityDesc(getContext().getConfig(), f.getFid(), 0x01);
                th.send(request, response, RequestParam.NO_RETRY);
            }

            SID ownerUser = response.securityDescriptor.owner_user;
            if ( ownerUser == null ) {
                return null;
            }

            if ( resolve ) {
                ownerUser.resolve(this.fileLocator.getServerWithDfs(), getContext());
            }
            return ownerUser;
        }
    }


    @Override
    public SID getOwnerGroup () throws IOException {
        return getOwnerGroup(true);
    }


    @Override
    public SID getOwnerGroup ( boolean resolve ) throws IOException {
        try ( SmbTreeHandleImpl th = ensureTreeConnected() ) {
            if ( !th.hasCapability(SmbConstants.CAP_NT_SMBS) ) {
                throw new SmbUnsupportedOperationException("Not supported without CAP_NT_SMBS");
            }

            NtTransQuerySecurityDescResponse response = new NtTransQuerySecurityDescResponse(getContext().getConfig());
            try ( SmbFileHandleImpl f = openUnshared(O_RDONLY, READ_CONTROL, DEFAULT_SHARING, 0, isDirectory() ? 1 : 0) ) {

                /*
                 * NtTrans Query Security Desc Request / Response
                 */
                NtTransQuerySecurityDesc request = new NtTransQuerySecurityDesc(getContext().getConfig(), f.getFid(), 0x02);
                th.send(request, response, RequestParam.NO_RETRY);
            }

            SID ownerGroup = response.securityDescriptor.owner_group;
            if ( ownerGroup == null ) {
                return null;
            }

            if ( resolve ) {
                ownerGroup.resolve(this.fileLocator.getServerWithDfs(), getContext());
            }
            return ownerGroup;
        }
    }


    @Override
    public ACE[] getShareSecurity ( boolean resolveSids ) throws IOException {
        try ( SmbTreeHandleInternal th = ensureTreeConnected() ) {
            th.ensureDFSResolved();
            String server = this.fileLocator.getServerWithDfs();
            ACE[] aces;
            MsrpcShareGetInfo rpc = new MsrpcShareGetInfo(server, th.getConnectedShare());
            try ( DcerpcHandle handle = DcerpcHandle.getHandle("ncacn_np:" + server + "[\\PIPE\\srvsvc]", getContext()) ) {
                handle.sendrecv(rpc);
                if ( rpc.retval != 0 )
                    throw new SmbException(rpc.retval, true);
                aces = rpc.getSecurity();
                if ( aces != null )
                    processAces(aces, resolveSids);
            }
            return aces;
        }
    }

}
