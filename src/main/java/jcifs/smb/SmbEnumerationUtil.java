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


import java.io.IOException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.Address;
import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.CloseableIterator;
import jcifs.Credentials;
import jcifs.ResourceFilter;
import jcifs.ResourceNameFilter;
import jcifs.SmbConstants;
import jcifs.SmbResource;
import jcifs.SmbResourceLocator;
import jcifs.dcerpc.DcerpcHandle;
import jcifs.dcerpc.msrpc.MsrpcDfsRootEnum;
import jcifs.dcerpc.msrpc.MsrpcShareEnum;
import jcifs.internal.smb1.net.NetShareEnum;
import jcifs.internal.smb1.net.NetShareEnumResponse;
import jcifs.internal.smb1.trans.SmbComTransaction;
import jcifs.internal.smb1.trans.SmbComTransactionResponse;


/**
 * @author mbechler
 *
 */
final class SmbEnumerationUtil {

    private static final Logger log = LoggerFactory.getLogger(SmbEnumerationUtil.class);


    /**
     * 
     */
    private SmbEnumerationUtil () {}


    private static String getRPCTarget ( CIFSContext ctx, SmbResourceLocator loc, Address serverAddress ) {
        // Try to stick to the same server. However if we are using kerberos authentication we need to use the name.
        // The comment about composite share lists was wrong, we do not iterate over multiple targets.
        Credentials creds = ctx.getCredentials();
        if ( creds instanceof Kerb5Authenticator && serverAddress.getHostName() != null ) {
            return serverAddress.getHostName();
        }
        return serverAddress.getHostAddress();
    }


    static FileEntry[] doDfsRootEnum ( CIFSContext ctx, SmbResourceLocator loc, Address address ) throws IOException {
        try ( DcerpcHandle handle = DcerpcHandle.getHandle("ncacn_np:" + getRPCTarget(ctx, loc, address) + "[\\PIPE\\netdfs]", ctx) ) {
            MsrpcDfsRootEnum rpc = new MsrpcDfsRootEnum(loc.getServer());
            handle.sendrecv(rpc);
            if ( rpc.retval != 0 ) {
                throw new SmbException(rpc.retval, true);
            }
            return rpc.getEntries();
        }
    }


    static FileEntry[] doMsrpcShareEnum ( CIFSContext ctx, SmbResourceLocator loc, Address address ) throws IOException {
        try ( DcerpcHandle handle = DcerpcHandle.getHandle("ncacn_np:" + getRPCTarget(ctx, loc, address) + "[\\PIPE\\srvsvc]", ctx) ) {
            MsrpcShareEnum rpc = new MsrpcShareEnum(loc.getServer());
            handle.sendrecv(rpc);
            if ( rpc.retval != 0 ) {
                throw new SmbException(rpc.retval, true);
            }
            return rpc.getEntries();
        }
    }


    static FileEntry[] doNetShareEnum ( SmbTreeHandleImpl th ) throws CIFSException {
        SmbComTransaction req = new NetShareEnum(th.getConfig());
        SmbComTransactionResponse resp = new NetShareEnumResponse(th.getConfig());
        th.send(req, resp);
        if ( resp.getStatus() != WinError.ERROR_SUCCESS )
            throw new SmbException(resp.getStatus(), true);

        return resp.getResults();
    }


    static CloseableIterator<SmbResource> doShareEnum ( SmbFile parent, String wildcard, int searchAttributes, ResourceNameFilter fnf,
            ResourceFilter ff ) throws CIFSException {
        // clone the locator so that the address index is not modified
        SmbResourceLocatorImpl locator = parent.fileLocator.clone();
        CIFSContext tc = parent.getContext();
        URL u = locator.getURL();

        FileEntry[] entries;

        if ( u.getPath().lastIndexOf('/') != ( u.getPath().length() - 1 ) )
            throw new SmbException(u.toString() + " directory must end with '/'");

        if ( locator.getType() != SmbConstants.TYPE_SERVER )
            throw new SmbException("The requested list operations is invalid: " + u.toString());

        Set<FileEntry> set = new HashSet<>();

        if ( tc.getDfs().isTrustedDomain(tc, locator.getServer()) ) {
            /*
             * The server name is actually the name of a trusted
             * domain. Add DFS roots to the list.
             */
            try {
                entries = doDfsRootEnum(tc, locator, locator.getAddress());
                for ( int ei = 0; ei < entries.length; ei++ ) {
                    FileEntry e = entries[ ei ];
                    if ( !set.contains(e) && ( fnf == null || fnf.accept(parent, e.getName()) ) ) {
                        set.add(e);
                    }
                }
            }
            catch ( IOException ioe ) {
                log.debug("DS enumeration failed", ioe);
            }
        }

        SmbTreeConnection treeConn = new SmbTreeConnection(tc);
        try ( SmbTreeHandleImpl th = treeConn.connectHost(locator, locator.getServerWithDfs());
              SmbSessionImpl session = th.getSession();
              SmbTransportImpl transport = session.getTransport() ) {
            try {
                entries = doMsrpcShareEnum(tc, locator, transport.getRemoteAddress());
            }
            catch ( IOException ioe ) {
                if ( th.isSMB2() ) {
                    throw ioe;
                }
                log.debug("doMsrpcShareEnum failed", ioe);
                entries = doNetShareEnum(th);
            }
            for ( int ei = 0; ei < entries.length; ei++ ) {
                FileEntry e = entries[ ei ];
                if ( !set.contains(e) && ( fnf == null || fnf.accept(parent, e.getName()) ) ) {
                    set.add(e);
                }
            }

        }
        catch ( SmbException e ) {
            throw e;
        }
        catch ( IOException ioe ) {
            log.debug("doNetShareEnum failed", ioe);
            throw new SmbException(u.toString(), ioe);
        }
        return new ShareEnumIterator(parent, set.iterator(), ff);
    }


    @SuppressWarnings ( "resource" )
    static CloseableIterator<SmbResource> doEnum ( SmbFile parent, String wildcard, int searchAttributes, ResourceNameFilter fnf, ResourceFilter ff )
            throws CIFSException {
        DosFileFilter dff = unwrapDOSFilter(ff);
        if ( dff != null ) {
            if ( dff.wildcard != null )
                wildcard = dff.wildcard;
            searchAttributes = dff.attributes;
        }
        SmbResourceLocator locator = parent.getLocator();
        if ( locator.getURL().getHost().isEmpty() ) {
            // smb:// -> enumerate servers through browsing
            Address addr;
            try {
                addr = locator.getAddress();
            }
            catch ( CIFSException e ) {
                if ( e.getCause() instanceof UnknownHostException ) {
                    log.debug("Failed to find master browser", e);
                    throw new SmbUnsupportedOperationException();
                }
                throw e;
            }
            try ( SmbFile browser = (SmbFile) parent.resolve(addr.getHostAddress()) ) {
                try ( SmbTreeHandleImpl th = browser.ensureTreeConnected() ) {
                    if ( th.isSMB2() ) {
                        throw new SmbUnsupportedOperationException();
                    }
                    return new NetServerFileEntryAdapterIterator(parent, new NetServerEnumIterator(parent, th, wildcard, searchAttributes, fnf), ff);
                }
            }
        }
        else if ( locator.getType() == SmbConstants.TYPE_WORKGROUP ) {
            try ( SmbTreeHandleImpl th = parent.ensureTreeConnected() ) {
                if ( th.isSMB2() ) {
                    throw new SmbUnsupportedOperationException();
                }
                return new NetServerFileEntryAdapterIterator(parent, new NetServerEnumIterator(parent, th, wildcard, searchAttributes, fnf), ff);
            }
        }
        else if ( locator.isRoot() ) {
            return doShareEnum(parent, wildcard, searchAttributes, fnf, ff);
        }

        try ( SmbTreeHandleImpl th = parent.ensureTreeConnected() ) {
            if ( th.isSMB2() ) {
                return new DirFileEntryAdapterIterator(parent, new DirFileEntryEnumIterator2(th, parent, wildcard, fnf, searchAttributes), ff);
            }
            return new DirFileEntryAdapterIterator(parent, new DirFileEntryEnumIterator1(th, parent, wildcard, fnf, searchAttributes), ff);
        }
    }


    private static DosFileFilter unwrapDOSFilter ( ResourceFilter ff ) {
        if ( ff instanceof ResourceFilterWrapper ) {
            SmbFileFilter sff = ( (ResourceFilterWrapper) ff ).getFileFilter();
            if ( sff instanceof DosFileFilter ) {
                return (DosFileFilter) sff;
            }
        }
        return null;
    }


    static String[] list ( SmbFile root, String wildcard, int searchAttributes, final SmbFilenameFilter fnf, final SmbFileFilter ff )
            throws SmbException {
        try ( CloseableIterator<SmbResource> it = doEnum(root, wildcard, searchAttributes, fnf == null ? null : new ResourceNameFilter() {

            @Override
            public boolean accept ( SmbResource parent, String name ) throws CIFSException {
                if ( ! ( parent instanceof SmbFile ) ) {
                    return false;
                }
                return fnf.accept((SmbFile) parent, name);
            }
        }, ff == null ? null : new ResourceFilter() {

            @Override
            public boolean accept ( SmbResource resource ) throws CIFSException {
                if ( ! ( resource instanceof SmbFile ) ) {
                    return false;
                }
                return ff.accept((SmbFile) resource);
            }
        }) ) {

            List<String> list = new ArrayList<>();
            while ( it.hasNext() ) {
                try ( SmbResource n = it.next() ) {
                    list.add(n.getName());
                }
            }
            return list.toArray(new String[list.size()]);
        }
        catch ( CIFSException e ) {
            throw SmbException.wrap(e);
        }
    }


    static SmbFile[] listFiles ( SmbFile root, String wildcard, int searchAttributes, final SmbFilenameFilter fnf, final SmbFileFilter ff )
            throws SmbException {
        try ( CloseableIterator<SmbResource> it = doEnum(
            root,
            wildcard,
            searchAttributes,
            fnf == null ? null : new ResourceNameFilterWrapper(fnf),
            ff == null ? null : new ResourceFilterWrapper(ff)) ) {

            List<SmbFile> list = new ArrayList<>();
            while ( it.hasNext() ) {
                try ( SmbResource n = it.next() ) {
                    if ( n instanceof SmbFile ) {
                        list.add((SmbFile) n);
                    }
                }
            }
            return list.toArray(new SmbFile[list.size()]);
        }
        catch ( CIFSException e ) {
            throw SmbException.wrap(e);
        }
    }

    /**
     * @author mbechler
     *
     */
    private static final class ResourceFilterWrapper implements ResourceFilter {

        /**
         * 
         */
        private final SmbFileFilter ff;


        /**
         * @param ff
         */
        ResourceFilterWrapper ( SmbFileFilter ff ) {
            this.ff = ff;
        }


        SmbFileFilter getFileFilter () {
            return this.ff;
        }


        @Override
        public boolean accept ( SmbResource resource ) throws CIFSException {
            if ( ! ( resource instanceof SmbFile ) ) {
                return false;
            }
            return this.ff.accept((SmbFile) resource);
        }
    }

    /**
     * @author mbechler
     *
     */
    private static final class ResourceNameFilterWrapper implements ResourceNameFilter {

        /**
         * 
         */
        private final SmbFilenameFilter fnf;


        /**
         * @param fnf
         */
        ResourceNameFilterWrapper ( SmbFilenameFilter fnf ) {
            this.fnf = fnf;
        }


        @Override
        public boolean accept ( SmbResource parent, String name ) throws CIFSException {
            if ( ! ( parent instanceof SmbFile ) ) {
                return false;
            }
            return this.fnf.accept((SmbFile) parent, name);
        }
    }

}
