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
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.RuntimeCIFSException;
import jcifs.SmbConstants;
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

public class SmbFile extends URLConnection implements SmbConstants, AutoCloseable {

    static final int O_RDONLY = 0x01;
    static final int O_WRONLY = 0x02;
    static final int O_RDWR = 0x03;
    static final int O_APPEND = 0x04;

    // Open Function Encoding
    // create if the file does not exist
    static final int O_CREAT = 0x0010;
    // fail if the file exists
    static final int O_EXCL = 0x0020;
    // truncate if the file exists
    static final int O_TRUNC = 0x0040;

    // share access
    /**
     * When specified as the <tt>shareAccess</tt> constructor parameter,
     * other SMB clients (including other threads making calls into jCIFS)
     * will not be permitted to access the target file and will receive "The
     * file is being accessed by another process" message.
     */
    public static final int FILE_NO_SHARE = 0x00;
    /**
     * When specified as the <tt>shareAccess</tt> constructor parameter,
     * other SMB clients will be permitted to read from the target file while
     * this file is open. This constant may be logically OR'd with other share
     * access flags.
     */
    public static final int FILE_SHARE_READ = 0x01;
    /**
     * When specified as the <tt>shareAccess</tt> constructor parameter,
     * other SMB clients will be permitted to write to the target file while
     * this file is open. This constant may be logically OR'd with other share
     * access flags.
     */
    public static final int FILE_SHARE_WRITE = 0x02;
    /**
     * When specified as the <tt>shareAccess</tt> constructor parameter,
     * other SMB clients will be permitted to delete the target file while
     * this file is open. This constant may be logically OR'd with other share
     * access flags.
     */
    public static final int FILE_SHARE_DELETE = 0x04;

    // file attribute encoding
    /**
     * A file with this bit on as returned by <tt>getAttributes()</tt> or set
     * with <tt>setAttributes()</tt> will be read-only
     */
    public static final int ATTR_READONLY = 0x01;
    /**
     * A file with this bit on as returned by <tt>getAttributes()</tt> or set
     * with <tt>setAttributes()</tt> will be hidden
     */
    public static final int ATTR_HIDDEN = 0x02;
    /**
     * A file with this bit on as returned by <tt>getAttributes()</tt> or set
     * with <tt>setAttributes()</tt> will be a system file
     */
    public static final int ATTR_SYSTEM = 0x04;
    /**
     * A file with this bit on as returned by <tt>getAttributes()</tt> is
     * a volume
     */
    public static final int ATTR_VOLUME = 0x08;
    /**
     * A file with this bit on as returned by <tt>getAttributes()</tt> is
     * a directory
     */
    public static final int ATTR_DIRECTORY = 0x10;
    /**
     * A file with this bit on as returned by <tt>getAttributes()</tt> or set
     * with <tt>setAttributes()</tt> is an archived file
     */
    public static final int ATTR_ARCHIVE = 0x20;

    /**
     * Returned by {@link #getType()} if the resource this <tt>SmbFile</tt>
     * represents is a regular file or directory.
     */
    public static final int TYPE_FILESYSTEM = 0x01;
    /**
     * Returned by {@link #getType()} if the resource this <tt>SmbFile</tt>
     * represents is a workgroup.
     */
    public static final int TYPE_WORKGROUP = 0x02;
    /**
     * Returned by {@link #getType()} if the resource this <tt>SmbFile</tt>
     * represents is a server.
     */
    public static final int TYPE_SERVER = 0x04;
    /**
     * Returned by {@link #getType()} if the resource this <tt>SmbFile</tt>
     * represents is a share.
     */
    public static final int TYPE_SHARE = 0x08;
    /**
     * Returned by {@link #getType()} if the resource this <tt>SmbFile</tt>
     * represents is a named pipe.
     */
    public static final int TYPE_NAMED_PIPE = 0x10;
    /**
     * Returned by {@link #getType()} if the resource this <tt>SmbFile</tt>
     * represents is a printer.
     */
    public static final int TYPE_PRINTER = 0x20;
    /**
     * Returned by {@link #getType()} if the resource this <tt>SmbFile</tt>
     * represents is a communications device.
     */
    public static final int TYPE_COMM = 0x40;

    // extended file attribute encoding(others same as above)
    static final int ATTR_COMPRESSED = 0x800;
    static final int ATTR_NORMAL = 0x080;
    static final int ATTR_TEMPORARY = 0x100;

    static final int ATTR_GET_MASK = 0x7FFF; /* orig 0x7fff */
    static final int ATTR_SET_MASK = 0x30A7; /* orig 0x0027 */

    static final int DEFAULT_ATTR_EXPIRATION_PERIOD = 5000;

    static final int HASH_DOT = ".".hashCode();
    static final int HASH_DOT_DOT = "..".hashCode();

    private static Logger log = LoggerFactory.getLogger(SmbFile.class);

    private long createTime;
    private long lastModified;
    private long lastAccess;
    private int attributes;
    private long attrExpiration;
    private long size;
    private long sizeExpiration;
    private boolean isExists;
    private int shareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

    private CIFSContext transportContext;
    private SmbTreeConnection treeConnection;
    protected final SmbFileLocatorImpl fileLocator;
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
    public SmbFile ( SmbFile context, String name ) throws MalformedURLException, UnknownHostException {
        this(
            context.getFileLocator().isWorkgroup() ? new URL(null, "smb://" + checkName(name), context.transportContext.getUrlHandler())
                    : new URL(context.getURL(), checkName(name), context.transportContext.getUrlHandler()),
            context.getTransportContext());
        setContext(context, name);
    }


    /**
     * Constructs an SmbFile representing a resource on an SMB network such
     * as a file or directory. The second parameter is a relative path from
     * the <code>context</code>. See the description above for examples of
     * using the second <code>name</code> parameter. The <tt>shareAccess</tt>
     * parameter controls what permissions other clients have when trying
     * to access the same file while this instance is still open. This
     * value is either <tt>FILE_NO_SHARE</tt> or any combination
     * of <tt>FILE_SHARE_READ</tt>, <tt>FILE_SHARE_WRITE</tt>, and
     * <tt>FILE_SHARE_DELETE</tt> logically OR'd together.
     *
     * @param context
     *            A base <code>SmbFile</code>
     * @param name
     *            A path string relative to the <code>context</code> file path
     * @param shareAccess
     *            Specifies what access other clients have while this file is open.
     * @throws MalformedURLException
     *             If the <code>context</code> and <code>name</code> parameters
     *             do not follow the prescribed syntax
     * @throws UnknownHostException
     */
    public SmbFile ( SmbFile context, String name, int shareAccess ) throws MalformedURLException, UnknownHostException {
        this(
            context.getFileLocator().isWorkgroup() ? new URL(null, "smb://" + checkName(name), context.getTransportContext().getUrlHandler())
                    : new URL(context.getURL(), checkName(name), context.getTransportContext().getUrlHandler()),
            context.transportContext);
        if ( ( shareAccess & ~ ( FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE ) ) != 0 ) {
            throw new RuntimeCIFSException("Illegal shareAccess parameter");
        }
        this.shareAccess = shareAccess;
        setContext(context, name);
    }


    /**
     * @param url
     * @param tc
     *            context to use
     * @param shareAccess
     *            Specifies what access other clients have while this file is open.
     * @throws MalformedURLException
     */
    public SmbFile ( String url, CIFSContext tc, int shareAccess ) throws MalformedURLException {
        this(new URL(null, url, tc.getUrlHandler()), tc);
        if ( ( shareAccess & ~ ( FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE ) ) != 0 ) {
            throw new RuntimeCIFSException("Illegal shareAccess parameter");
        }
        this.shareAccess = shareAccess;
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
        this.fileLocator = new SmbFileLocatorImpl(tc, url);
        this.treeConnection = new SmbTreeConnection(tc);
    }


    SmbFile ( SmbFile context, String name, boolean loadedAttributes, int type, int attributes, long createTime, long lastModified, long lastAccess,
            long size ) throws MalformedURLException, UnknownHostException {
        this(
            context.getFileLocator().isWorkgroup() ? new URL(null, "smb://" + checkName(name) + "/", Handler.SMB_HANDLER)
                    : new URL(context.url, checkName(name) + ( ( attributes & ATTR_DIRECTORY ) > 0 ? "/" : "" )),
            context.getTransportContext());

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
            this.attrExpiration = this.sizeExpiration = System.currentTimeMillis() + getTransportContext().getConfig().getAttributeCacheTimeout();
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
    private void setContext ( SmbFile context, String name ) {
        this.fileLocator.setContext(context.fileLocator, name);
        if ( context.getFileLocator().getShare() != null ) {
            this.treeConnection = new SmbTreeConnection(context.treeConnection);
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
        this.treeConnection.setNonPool(nonPooled);
    }


    /**
     * @return the transportContext
     */
    public CIFSContext getTransportContext () {
        return this.transportContext;
    }


    /**
     * @return the fileLocator
     */
    public SmbFileLocator getFileLocator () {
        return this.fileLocator;
    }


    SmbFileHandleImpl openUnshared ( int flags, int access, int attrs, int options ) throws SmbException {
        return openUnshared(getUncPath(), flags, access, attrs, options);
    }


    SmbFileHandleImpl openUnshared ( String uncPath, int flags, int access, int attrs, int options ) throws SmbException {
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
                SmbComNTCreateAndX request = new SmbComNTCreateAndX(config, uncPath, flags, access, this.shareAccess, attrs, options, null);
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
                h.send(new SmbComOpenAndX(config, uncPath, access, this.shareAccess, flags, null), response);
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
     * @return this file's unc path
     */
    public String getUncPath () {
        return this.fileLocator.getUncPath();
    }


    /**
     * @param request
     * @param response
     */
    protected void customizeCreate ( SmbComNTCreateAndX request, SmbComNTCreateAndXResponse response ) {}


    Info queryPath ( String path, int infoLevel ) throws SmbException {
        try ( SmbTreeHandleImpl th = ensureTreeConnected() ) {

            if ( log.isDebugEnabled() ) {
                log.debug("queryPath: " + path);
            }

            /*
             * normally we'd check the negotiatedCapabilities for CAP_NT_SMBS
             * however I can't seem to get a good last modified time from
             * SMB_COM_QUERY_INFORMATION so if NT_SMBs are requested
             * by the server than in this case that's what it will get
             * regardless of what jcifs.smb.client.useNTSmbs is set
             * to(overrides negotiatedCapabilities).
             */

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


    /**
     * Tests to see if the SMB resource exists. If the resource refers
     * only to a server, this method determines if the server exists on the
     * network and is advertising SMB services. If this resource refers to
     * a workgroup, this method determines if the workgroup name is valid on
     * the local SMB network. If this <code>SmbFile</code> refers to the root
     * <code>smb://</code> resource <code>true</code> is always returned. If
     * this <code>SmbFile</code> is a traditional file or directory, it will
     * be queried for on the specified server as expected.
     *
     * @return <code>true</code> if the resource exists or is alive or
     *         <code>false</code> otherwise
     * @throws SmbException
     */
    public boolean exists () throws SmbException {

        if ( this.attrExpiration > System.currentTimeMillis() ) {
            log.trace("Using cached attributes");
            return this.isExists;
        }

        this.fileLocator.getCanonicalResourcePath();

        this.attributes = ATTR_READONLY | ATTR_DIRECTORY;
        this.createTime = 0L;
        this.lastModified = 0L;
        this.lastAccess = 0L;
        this.isExists = false;

        try {
            if ( this.url.getHost().length() == 0 ) {}
            else if ( this.fileLocator.getShare() == null ) {
                if ( this.fileLocator.getType() == TYPE_WORKGROUP ) {
                    getTransportContext().getNameServiceClient().getByName(this.url.getHost(), true);
                }
                else {
                    getTransportContext().getNameServiceClient().getByName(this.url.getHost()).getHostName();
                }
            }
            else if ( this.fileLocator.isRoot() || this.fileLocator.isIPC() ) {
                // treeConnect is good enough
                try ( SmbTreeHandle th = this.ensureTreeConnected() ) {}
            }
            else {
                Info info = queryPath(this.fileLocator.getCanonicalResourcePath(), Trans2QueryPathInformationResponse.SMB_QUERY_FILE_BASIC_INFO);
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

        this.attrExpiration = System.currentTimeMillis() + getTransportContext().getConfig().getAttributeCacheTimeout();
        return this.isExists;
    }


    /**
     * Returns type of of object this <tt>SmbFile</tt> represents.
     * 
     * @return <tt>TYPE_FILESYSTEM, TYPE_WORKGROUP, TYPE_SERVER, TYPE_SHARE,
     * TYPE_PRINTER, TYPE_NAMED_PIPE</tt>, or <tt>TYPE_COMM</tt>.
     * @throws SmbException
     */
    public int getType () throws SmbException {
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
        return this.fileLocator.getCanonicalPath();
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
        String path = this.treeConnection.ensureDFSResolved(this.fileLocator).getDfsPath();
        if ( isDirectory() ) {
            path += '/';
        }
        return path;
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
        return this.fileLocator.getCanonicalPath();
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


    /**
     * Creates a directory watcher
     * 
     * @param filter
     *            see constants in {@link FileNotifyInformation}
     * @param recursive
     *            whether to also watch subdirectories
     * @return watch context
     * @throws SmbException
     */
    public SmbWatchHandleImpl watch ( int filter, boolean recursive ) throws SmbException {

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
            return new SmbWatchHandleImpl(openUnshared(O_RDONLY, READ_CONTROL, 0, 1), filter, recursive);
        }
    }


    /**
     * Tests to see if the file this <code>SmbFile</code> represents can be
     * read. Because any file, directory, or other resource can be read if it
     * exists, this method simply calls the <code>exists</code> method.
     *
     * @return <code>true</code> if the file is read-only
     * @throws SmbException
     */
    public boolean canRead () throws SmbException {
        if ( this.fileLocator.getType() == TYPE_NAMED_PIPE ) { // try opening the pipe for reading?
            return true;
        }
        return exists(); // try opening and catch sharing violation?
    }


    /**
     * Tests to see if the file this <code>SmbFile</code> represents
     * exists and is not marked read-only. By default, resources are
     * considered to be read-only and therefore for <code>smb://</code>,
     * <code>smb://workgroup/</code>, and <code>smb://server/</code> resources
     * will be read-only.
     *
     * @return <code>true</code> if the resource exists is not marked
     *         read-only
     * @throws SmbException
     */
    public boolean canWrite () throws SmbException {
        if ( this.fileLocator.getType() == TYPE_NAMED_PIPE ) { // try opening the pipe for writing?
            return true;
        }
        return exists() && ( this.attributes & ATTR_READONLY ) == 0;
    }


    /**
     * Tests to see if the file this <code>SmbFile</code> represents is a directory.
     *
     * @return <code>true</code> if this <code>SmbFile</code> is a directory
     * @throws SmbException
     */
    public boolean isDirectory () throws SmbException {
        if ( this.fileLocator.isRoot() ) {
            return true;
        }
        if ( !exists() )
            return false;
        return ( this.attributes & ATTR_DIRECTORY ) == ATTR_DIRECTORY;
    }


    /**
     * Tests to see if the file this <code>SmbFile</code> represents is not a directory.
     *
     * @return <code>true</code> if this <code>SmbFile</code> is not a directory
     * @throws SmbException
     */
    public boolean isFile () throws SmbException {
        if ( this.fileLocator.isRoot() ) {
            return false;
        }
        exists();
        return ( this.attributes & ATTR_DIRECTORY ) == 0;
    }


    /**
     * Tests to see if the file this SmbFile represents is marked as
     * hidden. This method will also return true for shares with names that
     * end with '$' such as <code>IPC$</code> or <code>C$</code>.
     *
     * @return <code>true</code> if the <code>SmbFile</code> is marked as being hidden
     * @throws SmbException
     */
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


    /**
     * Retrieve the time this <code>SmbFile</code> was created. The value
     * returned is suitable for constructing a {@link java.util.Date} object
     * (i.e. seconds since Epoch 1970). Times should be the same as those
     * reported using the properties dialog of the Windows Explorer program.
     *
     * For Win95/98/Me this is actually the last write time. It is currently
     * not possible to retrieve the create time from files on these systems.
     *
     * @return The number of milliseconds since the 00:00:00 GMT, January 1,
     *         1970 as a <code>long</code> value
     * @throws SmbException
     */
    public long createTime () throws SmbException {
        if ( !this.fileLocator.isRoot() ) {
            exists();
            return this.createTime;
        }
        return 0L;
    }


    /**
     * Retrieve the last time the file represented by this
     * <code>SmbFile</code> was modified. The value returned is suitable for
     * constructing a {@link java.util.Date} object (i.e. seconds since Epoch
     * 1970). Times should be the same as those reported using the properties
     * dialog of the Windows Explorer program.
     *
     * @return The number of milliseconds since the 00:00:00 GMT, January 1,
     *         1970 as a <code>long</code> value
     * @throws SmbException
     */
    public long lastModified () throws SmbException {
        if ( !this.fileLocator.isRoot() ) {
            exists();
            return this.lastModified;
        }
        return 0L;
    }


    /**
     * Retrieve the last acces time of the file represented by this <code>SmbFile</code>
     * 
     * @return The number of milliseconds since the 00:00:00 GMT, January 1,
     *         1970 as a <code>long</code> value
     * @throws SmbException
     */
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
        return list("*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, null, null);
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
        return list("*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, filter, null);
    }


    /**
     * List the contents of this SMB resource as an array of
     * <code>SmbFile</code> objects. This method is much more efficient than
     * the regular <code>list</code> method when querying attributes of each
     * file in the result set.
     * <p>
     * The list of <code>SmbFile</code>s returned by this method will be;
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
     * @return An array of <code>SmbFile</code> objects representing file
     *         and directories, workgroups, servers, or shares depending on the context
     *         of the resource URL
     * @throws SmbException
     */
    public SmbFile[] listFiles () throws SmbException {
        return listFiles("*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, null, null);
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
     * @return An array of <code>SmbFile</code> objects representing file
     *         and directories, workgroups, servers, or shares depending on the context
     *         of the resource URL
     */

    public SmbFile[] listFiles ( String wildcard ) throws SmbException {
        return listFiles(wildcard, ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, null, null);
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
     * @return An array of <tt>SmbFile</tt> objects
     * @throws SmbException
     */
    public SmbFile[] listFiles ( SmbFilenameFilter filter ) throws SmbException {
        return listFiles("*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, filter, null);
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
     * @return An array of <tt>SmbFile</tt> objects
     * @throws SmbException
     */
    public SmbFile[] listFiles ( SmbFileFilter filter ) throws SmbException {
        return listFiles("*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, null, filter);
    }


    String[] list ( String wildcard, int searchAttributes, SmbFilenameFilter fnf, SmbFileFilter ff ) throws SmbException {
        List<Object> list = SmbEnumerationUtil.doEnum(this, false, wildcard, searchAttributes, fnf, ff);;
        return list.toArray(new String[list.size()]);
    }


    SmbFile[] listFiles ( String wildcard, int searchAttributes, SmbFilenameFilter fnf, SmbFileFilter ff ) throws SmbException {
        List<Object> list = SmbEnumerationUtil.doEnum(this, true, wildcard, searchAttributes, fnf, ff);
        return list.toArray(new SmbFile[list.size()]);
    }


    /**
     * Changes the name of the file this <code>SmbFile</code> represents to the name
     * designated by the <code>SmbFile</code> argument.
     * <br>
     * <i>Remember: <code>SmbFile</code>s are immutible and therefore
     * the path associated with this <code>SmbFile</code> object will not
     * change). To access the renamed file it is necessary to construct a
     * new <tt>SmbFile</tt></i>.
     *
     * @param dest
     *            An <code>SmbFile</code> that represents the new pathname
     * @throws SmbException
     * @throws NullPointerException
     *             If the <code>dest</code> argument is <code>null</code>
     */
    public void renameTo ( SmbFile dest ) throws SmbException {
        try ( SmbTreeHandleImpl sh = ensureTreeConnected();
              SmbTreeHandleImpl th = dest.ensureTreeConnected() ) {
            sh.ensureDFSResolved();
            th.ensureDFSResolved();

            if ( this.fileLocator.isRoot() || dest.getFileLocator().isRoot() ) {
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
    }


    void copyRecursive ( SmbFile dest, byte[][] b, int bsize, WriterThread w, SmbTreeHandleImpl sh, SmbTreeHandleImpl dh ) throws SmbException {
        if ( this.attrExpiration < System.currentTimeMillis() ) {
            this.attributes = ATTR_READONLY | ATTR_DIRECTORY;
            this.createTime = 0L;
            this.lastModified = 0L;
            this.isExists = false;

            Info info = queryPath(this.fileLocator.getCanonicalResourcePath(), Trans2QueryPathInformationResponse.SMB_QUERY_FILE_BASIC_INFO);
            this.attributes = info.getAttributes();
            this.createTime = info.getCreateTime();
            this.lastModified = info.getLastWriteTime();

            /*
             * If any of the above fails, isExists will not be set true
             */

            this.isExists = true;
            this.attrExpiration = System.currentTimeMillis() + getTransportContext().getConfig().getAttributeCacheTimeout();
        }

        if ( isDirectory() ) {
            SmbCopyUtil.copyDir(this, dest, b, bsize, w, sh, dh);
        }
        else {
            SmbCopyUtil.copyFile(this, dest, b, bsize, w, sh, dh);
        }
    }


    /**
     * This method will copy the file or directory represented by this
     * <tt>SmbFile</tt> and it's sub-contents to the location specified by the
     * <tt>dest</tt> parameter. This file and the destination file do not
     * need to be on the same host. This operation does not copy extended
     * file attibutes such as ACLs but it does copy regular attributes as
     * well as create and last write times. This method is almost twice as
     * efficient as manually copying as it employs an additional write
     * thread to read and write data concurrently.
     * <br>
     * It is not possible (nor meaningful) to copy entire workgroups or
     * servers.
     *
     * @param dest
     *            the destination file or directory
     * @throws SmbException
     */
    public void copyTo ( SmbFile dest ) throws SmbException {

        try ( SmbTreeHandleImpl sh = ensureTreeConnected();
              SmbTreeHandleImpl dh = dest.ensureTreeConnected() ) {

            sh.ensureDFSResolved();
            dh.ensureDFSResolved();

            /*
             * Should be able to copy an entire share actually
             */
            if ( this.fileLocator.getShare() == null || dest.getFileLocator().getShare() == null ) {
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
            try {
                if ( this.fileLocator.overlaps(dest.getFileLocator()) ) {
                    throw new SmbException("Source and destination paths overlap.");
                }
            }
            catch ( UnknownHostException uhe ) {
                log.debug("Unknown host", uhe);
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
    }


    /**
     * This method will delete the file or directory specified by this
     * <code>SmbFile</code>. If the target is a directory, the contents of
     * the directory will be deleted as well. If a file within the directory or
     * it's sub-directories is marked read-only, the read-only status will
     * be removed and the file will be deleted.
     * 
     * If the file has been opened before, it will be closed.
     *
     * @throws SmbException
     */
    public void delete () throws SmbException {
        exists();
        this.fileLocator.getCanonicalResourcePath();
        delete(getUncPath());
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


    void delete ( String fileName ) throws SmbException {
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

                Info info = queryPath(this.fileLocator.getCanonicalResourcePath(), Trans2QueryPathInformationResponse.SMB_QUERY_FILE_BASIC_INFO);
                this.attributes = info.getAttributes();
                this.createTime = info.getCreateTime();
                this.lastModified = info.getLastWriteTime();
                this.lastAccess = info.getLastAccessTime();

                this.attrExpiration = System.currentTimeMillis() + getTransportContext().getConfig().getAttributeCacheTimeout();
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

                try {
                    SmbFile[] l = listFiles("*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, null, null);
                    for ( int i = 0; i < l.length; i++ ) {
                        l[ i ].delete();
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


    /**
     * Returns the length of this <tt>SmbFile</tt> in bytes. If this object
     * is a <tt>TYPE_SHARE</tt> the total capacity of the disk shared in
     * bytes is returned. If this object is a directory or a type other than
     * <tt>TYPE_SHARE</tt>, 0L is returned.
     *
     * @return The length of the file in bytes or 0 if this
     *         <code>SmbFile</code> is not a file.
     * @throws SmbException
     */

    public long length () throws SmbException {
        if ( this.sizeExpiration > System.currentTimeMillis() ) {
            return this.size;
        }

        if ( this.fileLocator.getType() == TYPE_SHARE ) {
            try ( SmbTreeHandleImpl th = ensureTreeConnected() ) {
                int level = Trans2QueryFSInformationResponse.SMB_INFO_ALLOCATION;
                Trans2QueryFSInformationResponse response = new Trans2QueryFSInformationResponse(th.getConfig(), level);
                th.send(new Trans2QueryFSInformation(th.getConfig(), level), response);

                this.size = response.info.getCapacity();
            }
        }
        else if ( !this.fileLocator.isRoot() && this.fileLocator.getType() != TYPE_NAMED_PIPE ) {
            Info info = queryPath(this.fileLocator.getCanonicalResourcePath(), Trans2QueryPathInformationResponse.SMB_QUERY_FILE_STANDARD_INFO);
            this.size = info.getSize();
        }
        else {
            this.size = 0L;
        }
        this.sizeExpiration = System.currentTimeMillis() + getTransportContext().getConfig().getAttributeCacheTimeout();
        return this.size;
    }


    /**
     * This method returns the free disk space in bytes of the drive this share
     * represents or the drive on which the directory or file resides. Objects
     * other than <tt>TYPE_SHARE</tt> or <tt>TYPE_FILESYSTEM</tt> will result
     * in 0L being returned.
     *
     * @return the free disk space in bytes of the drive on which this file or
     *         directory resides
     * @throws SmbException
     */
    public long getDiskFreeSpace () throws SmbException {
        if ( this.fileLocator.getType() == TYPE_SHARE || this.fileLocator.getType() == TYPE_FILESYSTEM ) {
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


    private long queryFSInformation ( int level ) throws SmbException {
        try ( SmbTreeHandleImpl th = ensureTreeConnected() ) {
            Trans2QueryFSInformationResponse response = new Trans2QueryFSInformationResponse(th.getConfig(), level);
            th.send(new Trans2QueryFSInformation(th.getConfig(), level), response);

            if ( this.fileLocator.getType() == TYPE_SHARE ) {
                this.size = response.info.getCapacity();
                this.sizeExpiration = System.currentTimeMillis() + getTransportContext().getConfig().getAttributeCacheTimeout();
            }

            return response.info.getFree();
        }
    }


    /**
     * Creates a directory with the path specified by this
     * <code>SmbFile</code>. For this method to be successful, the target
     * must not already exist. This method will fail when
     * used with <code>smb://</code>, <code>smb://workgroup/</code>,
     * <code>smb://server/</code>, or <code>smb://server/share/</code> URLs
     * because workgroups, servers, and shares cannot be dynamically created
     * (although in the future it may be possible to create shares).
     *
     * @throws SmbException
     */
    public void mkdir () throws SmbException {
        String path = this.fileLocator.getCanonicalResourcePath();

        if ( path.length() == 1 ) {
            throw new SmbException("Invalid operation for workgroups, servers, or shares");
        }

        try ( SmbTreeHandleImpl th = ensureTreeConnected() ) {
            exists();
            th.ensureDFSResolved();

            // get the path again, this may have changed through DFS referrals
            path = this.fileLocator.getCanonicalResourcePath();

            /*
             * Create Directory Request / Response
             */

            if ( log.isDebugEnabled() ) {
                log.debug("mkdir: " + path);
            }

            th.send(new SmbComCreateDirectory(th.getConfig(), path), new SmbComBlankResponse(th.getConfig()));
            this.attrExpiration = this.sizeExpiration = 0;
        }
    }


    /**
     * Creates a directory with the path specified by this <tt>SmbFile</tt>
     * and any parent directories that do not exist. This method will fail
     * when used with <code>smb://</code>, <code>smb://workgroup/</code>,
     * <code>smb://server/</code>, or <code>smb://server/share/</code> URLs
     * because workgroups, servers, and shares cannot be dynamically created
     * (although in the future it may be possible to create shares).
     *
     * @throws SmbException
     */
    public void mkdirs () throws SmbException {
        try ( SmbTreeHandle th = ensureTreeConnected();
              SmbFile parent = new SmbFile(this.fileLocator.getParent(), getTransportContext()) ) {
            if ( parent.exists() == false ) {
                parent.mkdirs();
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
        catch ( MalformedURLException e ) {
            throw new SmbException("Invalid URL in mkdirs", e);
        }
    }


    /**
     * Create a new file but fail if it already exists. The check for
     * existance of the file and it's creation are an atomic operation with
     * respect to other filesystem activities.
     * 
     * @throws SmbException
     */
    public void createNewFile () throws SmbException {
        if ( this.fileLocator.isRoot() ) {
            throw new SmbException("Invalid operation for workgroups, servers, or shares");
        }

        try ( SmbFileHandle fd = openUnshared(O_RDWR | O_CREAT | O_EXCL, 0, ATTR_NORMAL, 0) ) {
            // close explicitly
            fd.close(0L);
        }
    }


    void setPathInformation ( int attrs, long ctime, long mtime, long atime ) throws SmbException {
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
                try ( SmbFileHandleImpl f = openUnshared(O_RDONLY, FILE_WRITE_ATTRIBUTES, dir, dir != 0 ? 0x0001 : 0x0040) ) {
                    th.send(
                        new Trans2SetFileInformation(th.getConfig(), f.getFid(), attrs | dir, ctime, mtime, atime),
                        new Trans2SetFileInformationResponse(th.getConfig()),
                        RequestParam.NO_RETRY);
                }
            }
            this.attrExpiration = 0;
        }
    }


    /**
     * Set the create time of the file. The time is specified as milliseconds
     * from Jan 1, 1970 which is the same as that which is returned by the
     * <tt>createTime()</tt> method.
     * <br>
     * This method does not apply to workgroups, servers, or shares.
     *
     * @param time
     *            the create time as milliseconds since Jan 1, 1970
     * @throws SmbException
     */
    public void setCreateTime ( long time ) throws SmbException {
        if ( this.fileLocator.isRoot() ) {
            throw new SmbException("Invalid operation for workgroups, servers, or shares");
        }

        setPathInformation(0, time, 0L, 0L);
    }


    /**
     * Set the last modified time of the file. The time is specified as milliseconds
     * from Jan 1, 1970 which is the same as that which is returned by the
     * <tt>lastModified()</tt>, <tt>getLastModified()</tt>, and <tt>getDate()</tt> methods.
     * <br>
     * This method does not apply to workgroups, servers, or shares.
     *
     * @param time
     *            the last modified time as milliseconds since Jan 1, 1970
     * @throws SmbException
     */
    public void setLastModified ( long time ) throws SmbException {
        if ( this.fileLocator.isRoot() ) {
            throw new SmbException("Invalid operation for workgroups, servers, or shares");
        }

        setPathInformation(0, 0L, time, 0L);
    }


    /**
     * Set the last accesss time of the file. The time is specified as milliseconds
     * from Jan 1, 1970 which is the same as that which is returned by the
     * <tt>lastModified()</tt>, <tt>getLastModified()</tt>, and <tt>getDate()</tt> methods.
     * <br>
     * This method does not apply to workgroups, servers, or shares.
     *
     * @param time
     *            the last access time as milliseconds since Jan 1, 1970
     * @throws SmbException
     */
    public void setLastAccess ( long time ) throws SmbException {
        if ( this.fileLocator.isRoot() ) {
            throw new SmbException("Invalid operation for workgroups, servers, or shares");
        }

        setPathInformation(0, 0L, 0L, time);
    }


    /**
     * Return the attributes of this file. Attributes are represented as a
     * bitset that must be masked with <tt>ATTR_*</tt> constants to determine
     * if they are set or unset. The value returned is suitable for use with
     * the <tt>setAttributes()</tt> method.
     *
     * @return the <tt>ATTR_*</tt> attributes associated with this file
     * @throws SmbException
     */
    public int getAttributes () throws SmbException {
        if ( this.fileLocator.isRoot() ) {
            return 0;
        }
        exists();
        return this.attributes & ATTR_GET_MASK;
    }


    /**
     * Set the attributes of this file. Attributes are composed into a
     * bitset by bitwise ORing the <tt>ATTR_*</tt> constants. Setting the
     * value returned by <tt>getAttributes</tt> will result in both files
     * having the same attributes.
     * 
     * @param attrs
     *            attribute flags
     * 
     * @throws SmbException
     */
    public void setAttributes ( int attrs ) throws SmbException {
        if ( this.fileLocator.isRoot() ) {
            throw new SmbException("Invalid operation for workgroups, servers, or shares");
        }
        setPathInformation(attrs & ATTR_SET_MASK, 0L, 0L, 0L);
    }


    /**
     * Make this file read-only. This is shorthand for <tt>setAttributes(
     * getAttributes() | ATTR_READ_ONLY )</tt>.
     *
     * @throws SmbException
     */
    public void setReadOnly () throws SmbException {
        setAttributes(getAttributes() | ATTR_READONLY);
    }


    /**
     * Turn off the read-only attribute of this file. This is shorthand for
     * <tt>setAttributes( getAttributes() &amp; ~ATTR_READONLY )</tt>.
     *
     * @throws SmbException
     */
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
        return this.getURL();
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
            SmbFile f = (SmbFile) obj;

            if ( this == f )
                return true;

            return this.fileLocator.equals(f.getFileLocator());
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


    /**
     * This URLConnection method just returns a new <tt>SmbFileOutputStream</tt> created with this file.
     *
     * @throws IOException
     *             thrown by <tt>SmbFileOutputStream</tt> constructor
     */
    @Override
    public OutputStream getOutputStream () throws IOException {
        return new SmbFileOutputStream(this);
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

                getTransportContext().getSIDResolver().resolveSids(getTransportContext(), server, sids, off, len);
            }
        }
        else {
            for ( ai = 0; ai < aces.length; ai++ ) {
                aces[ ai ].sid.origin_server = server;
                aces[ ai ].sid.origin_ctx = getTransportContext();
            }
        }
    }


    /**
     * Get the file index
     * 
     * @return server side file index, 0 if unavailable
     * @throws SmbException
     */
    public long fileIndex () throws SmbException {
        return 0;
    }


    /**
     * Return an array of Access Control Entry (ACE) objects representing
     * the security descriptor associated with this file or directory.
     * If no DACL is present, null is returned. If the DACL is empty, an array with 0 elements is returned.
     * 
     * @param resolveSids
     *            Attempt to resolve the SIDs within each ACE form
     *            their numeric representation to their corresponding account names.
     * @return array of ACEs
     * @throws IOException
     */
    public ACE[] getSecurity ( boolean resolveSids ) throws IOException {
        try ( SmbTreeHandleImpl th = ensureTreeConnected() ) {
            if ( !th.hasCapability(SmbConstants.CAP_NT_SMBS) ) {
                throw new SmbUnsupportedOperationException("Not supported without CAP_NT_SMBS");
            }

            ACE[] aces;

            NtTransQuerySecurityDescResponse response = new NtTransQuerySecurityDescResponse(th.getConfig());
            try ( SmbFileHandleImpl f = openUnshared(O_RDONLY, READ_CONTROL, 0, isDirectory() ? 1 : 0) ) {
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


    /**
     * Return the resolved owner user SID for this file or directory
     * 
     * @return the owner user SID, <code>null</code> if not present
     * @throws IOException
     */
    public SID getOwnerUser () throws IOException {
        return getOwnerUser(true);
    }


    /**
     * Return the owner user SID for this file or directory
     * 
     * @param resolve
     *            whether to resolve the user name
     * @return the owner user SID, <code>null</code> if not present
     * @throws IOException
     */
    public SID getOwnerUser ( boolean resolve ) throws IOException {
        try ( SmbTreeHandleImpl th = ensureTreeConnected() ) {
            if ( !th.hasCapability(SmbConstants.CAP_NT_SMBS) ) {
                throw new SmbUnsupportedOperationException("Not supported without CAP_NT_SMBS");
            }
            NtTransQuerySecurityDescResponse response = new NtTransQuerySecurityDescResponse(getTransportContext().getConfig());

            try ( SmbFileHandleImpl f = openUnshared(O_RDONLY, READ_CONTROL, 0, isDirectory() ? 1 : 0) ) {
                /*
                 * NtTrans Query Security Desc Request / Response
                 */
                NtTransQuerySecurityDesc request = new NtTransQuerySecurityDesc(getTransportContext().getConfig(), f.getFid(), 0x01);
                th.send(request, response, RequestParam.NO_RETRY);
            }

            SID ownerUser = response.securityDescriptor.owner_user;
            if ( ownerUser == null ) {
                return null;
            }

            ownerUser.resolve(this.fileLocator.getServerWithDfs(), getTransportContext());
            return ownerUser;
        }
    }


    /**
     * Return the resolved owner group SID for this file or directory
     * 
     * @return the owner group SID, <code>null</code> if not present
     * @throws IOException
     */
    public SID getOwnerGroup () throws IOException {
        return getOwnerGroup(true);
    }


    /**
     * Return the owner group SID for this file or directory
     * 
     * @param resolve
     *            whether to resolve the group name
     * @return the owner group SID, <code>null</code> if not present
     * @throws IOException
     */
    public SID getOwnerGroup ( boolean resolve ) throws IOException {
        try ( SmbTreeHandleImpl th = ensureTreeConnected() ) {
            if ( !th.hasCapability(SmbConstants.CAP_NT_SMBS) ) {
                throw new SmbUnsupportedOperationException("Not supported without CAP_NT_SMBS");
            }

            NtTransQuerySecurityDescResponse response = new NtTransQuerySecurityDescResponse(getTransportContext().getConfig());
            try ( SmbFileHandleImpl f = openUnshared(O_RDONLY, READ_CONTROL, 0, isDirectory() ? 1 : 0) ) {

                /*
                 * NtTrans Query Security Desc Request / Response
                 */
                NtTransQuerySecurityDesc request = new NtTransQuerySecurityDesc(getTransportContext().getConfig(), f.getFid(), 0x02);
                th.send(request, response, RequestParam.NO_RETRY);
            }

            SID ownerGroup = response.securityDescriptor.owner_group;
            if ( ownerGroup == null ) {
                return null;
            }

            ownerGroup.resolve(this.fileLocator.getServerWithDfs(), getTransportContext());
            return ownerGroup;
        }
    }


    /**
     * Return an array of Access Control Entry (ACE) objects representing
     * the share permissions on the share exporting this file or directory.
     * If no DACL is present, null is returned. If the DACL is empty, an array with 0 elements is returned.
     * <p>
     * Note that this is different from calling <tt>getSecurity</tt> on a
     * share. There are actually two different ACLs for shares - the ACL on
     * the share and the ACL on the folder being shared.
     * Go to <i>Computer Management</i>
     * &gt; <i>System Tools</i> &gt; <i>Shared Folders</i> &gt; <i>Shares</i> and
     * look at the <i>Properties</i> for a share. You will see two tabs - one
     * for "Share Permissions" and another for "Security". These correspond to
     * the ACLs returned by <tt>getShareSecurity</tt> and <tt>getSecurity</tt>
     * respectively.
     * 
     * @param resolveSids
     *            Attempt to resolve the SIDs within each ACE form
     *            their numeric representation to their corresponding account names.
     * @return array of ACEs
     * @throws IOException
     */
    public ACE[] getShareSecurity ( boolean resolveSids ) throws IOException {
        try ( SmbTreeHandle th = ensureTreeConnected() ) {
            th.ensureDFSResolved();
            String server = this.fileLocator.getServerWithDfs();
            ACE[] aces;
            MsrpcShareGetInfo rpc = new MsrpcShareGetInfo(server, th.getConnectedShare());
            try ( DcerpcHandle handle = DcerpcHandle.getHandle("ncacn_np:" + server + "[\\PIPE\\srvsvc]", getTransportContext()) ) {
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


    /**
     * Return an array of Access Control Entry (ACE) objects representing
     * the security descriptor associated with this file or directory.
     * <p>
     * Initially, the SIDs within each ACE will not be resolved however when
     * <tt>getType()</tt>, <tt>getDomainName()</tt>, <tt>getAccountName()</tt>,
     * or <tt>toString()</tt> is called, the names will attempt to be
     * resolved. If the names cannot be resolved (e.g. due to temporary
     * network failure), the said methods will return default values (usually
     * <tt>S-X-Y-Z</tt> strings of fragments of).
     * <p>
     * Alternatively <tt>getSecurity(true)</tt> may be used to resolve all
     * SIDs together and detect network failures.
     * 
     * @return array of ACEs
     * @throws IOException
     */
    public ACE[] getSecurity () throws IOException {
        return getSecurity(false);
    }

}
