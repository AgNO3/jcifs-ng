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
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.Address;
import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.SmbConstants;
import jcifs.SmbResourceLocator;
import jcifs.dcerpc.DcerpcHandle;
import jcifs.dcerpc.msrpc.MsrpcDfsRootEnum;
import jcifs.dcerpc.msrpc.MsrpcShareEnum;


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


    static FileEntry[] doDfsRootEnum ( CIFSContext ctx, SmbResourceLocator loc ) throws IOException {
        MsrpcDfsRootEnum rpc;
        try ( DcerpcHandle handle = DcerpcHandle.getHandle("ncacn_np:" + loc.getAddress().getHostAddress() + "[\\PIPE\\netdfs]", ctx) ) {
            rpc = new MsrpcDfsRootEnum(loc.getServer());
            handle.sendrecv(rpc);
            if ( rpc.retval != 0 )
                throw new SmbException(rpc.retval, true);
            return rpc.getEntries();
        }
    }


    static FileEntry[] doMsrpcShareEnum ( CIFSContext ctx, String host, Address address ) throws IOException {
        MsrpcShareEnum rpc = new MsrpcShareEnum(host);
        /*
         * JCIFS will build a composite list of shares if the target host has
         * multiple IP addresses such as when domain-based DFS is in play. Because
         * of this, to ensure that we query each IP individually without re-resolving
         * the hostname and getting a different IP, we must use the current addresses
         * IP rather than just url.getHost() like we were using prior to 1.2.16.
         */
        try ( DcerpcHandle handle = DcerpcHandle.getHandle("ncacn_np:" + address.getHostAddress() + "[\\PIPE\\srvsvc]", ctx) ) {
            handle.sendrecv(rpc);
            if ( rpc.retval != 0 )
                throw new SmbException(rpc.retval, true);
            return rpc.getEntries();
        }
    }


    static FileEntry[] doNetShareEnum ( SmbTreeHandleImpl th ) throws CIFSException {
        SmbComTransaction req = new NetShareEnum(th.getConfig());
        SmbComTransactionResponse resp = new NetShareEnumResponse(th.getConfig());
        th.send(req, resp);
        if ( resp.status != WinError.ERROR_SUCCESS )
            throw new SmbException(resp.status, true);

        return resp.results;
    }


    static void doNetServerEnum ( SmbFile parent, SmbTreeHandleImpl th, List<Object> list, boolean files, String wildcard, int searchAttributes,
            SmbFilenameFilter fnf, SmbFileFilter ff ) throws CIFSException, MalformedURLException {
        SmbResourceLocatorImpl locator = parent.fileLocator;
        int listType = locator.getURL().getHost().isEmpty() ? 0 : locator.getType();
        SmbComTransaction req;
        SmbComTransactionResponse resp;

        if ( listType == 0 ) {
            req = new NetServerEnum2(th.getConfig(), th.getOEMDomainName(), NetServerEnum2.SV_TYPE_DOMAIN_ENUM);
            resp = new NetServerEnum2Response(th.getConfig());
        }
        else if ( listType == SmbConstants.TYPE_WORKGROUP ) {
            req = new NetServerEnum2(th.getConfig(), locator.getURL().getHost(), NetServerEnum2.SV_TYPE_ALL);
            resp = new NetServerEnum2Response(th.getConfig());
        }
        else {
            throw new SmbException("The requested list operations is invalid: " + locator.getURL().toString());
        }

        boolean more;
        do {
            int n;

            th.send(req, resp);

            if ( resp.status != WinError.ERROR_SUCCESS && resp.status != WinError.ERROR_MORE_DATA ) {
                throw new SmbException(resp.status, true);
            }
            more = resp.status == WinError.ERROR_MORE_DATA;

            n = more ? resp.numEntries - 1 : resp.numEntries;
            for ( int i = 0; i < n; i++ ) {
                FileEntry e = resp.results[ i ];
                String name = e.getName();
                if ( fnf != null && fnf.accept(parent, name) == false )
                    continue;
                if ( name.length() > 0 ) {
                    // if !files we don't need to create SmbFiles here
                    try ( SmbFile f = new SmbFile(
                        parent,
                        name,
                        false,
                        e.getType(),
                        SmbConstants.ATTR_READONLY | SmbConstants.ATTR_DIRECTORY,
                        0L,
                        0L,
                        0L,
                        0L) ) {
                        if ( ff != null && ff.accept(f) == false )
                            continue;
                        if ( files ) {
                            list.add(f);
                        }
                        else {
                            list.add(name);
                        }
                    }
                }
            }
            if ( locator.getType() != SmbConstants.TYPE_WORKGROUP ) {
                break;
            }
            req.subCommand = (byte) SmbComTransaction.NET_SERVER_ENUM3;
            req.reset(0, ( (NetServerEnum2Response) resp ).lastName);
            resp.reset();
        }
        while ( more );
    }


    static void doFindFirstNext ( SmbFile parent, SmbTreeHandleImpl th, List<Object> list, boolean files, String wildcard, int searchAttributes,
            SmbFilenameFilter fnf, SmbFileFilter ff ) throws CIFSException, MalformedURLException {
        SmbResourceLocatorImpl loc = parent.fileLocator;
        String path = loc.getUNCPath();
        String p = loc.getURL().getPath();

        if ( p.lastIndexOf('/') != ( p.length() - 1 ) ) {
            throw new SmbException(loc.getURL() + " directory must end with '/'");
        }

        SmbComTransaction req = new Trans2FindFirst2(th.getConfig(), path, wildcard, searchAttributes);
        Trans2FindFirst2Response resp = new Trans2FindFirst2Response(th.getConfig());

        if ( log.isDebugEnabled() ) {
            log.debug("doFindFirstNext: " + req.path);
        }

        th.send(req, resp);

        int sid = resp.sid;
        req = new Trans2FindNext2(th.getConfig(), sid, resp.resumeKey, resp.lastName);

        /*
         * The only difference between first2 and next2 responses is subCommand
         * so let's recycle the response object.
         */
        resp.subCommand = SmbComTransaction.TRANS2_FIND_NEXT2;

        for ( ;; ) {
            for ( int i = 0; i < resp.numEntries; i++ ) {
                FileEntry e = resp.results[ i ];
                String name = e.getName();
                if ( name.length() < 3 ) {
                    int h = name.hashCode();
                    if ( h == SmbFile.HASH_DOT || h == SmbFile.HASH_DOT_DOT ) {
                        if ( name.equals(".") || name.equals("..") )
                            continue;
                    }
                }
                if ( fnf != null && fnf.accept(parent, name) == false ) {
                    continue;
                }
                if ( name.length() > 0 ) {
                    try ( SmbFile f = new SmbFile(
                        parent,
                        name,
                        true,
                        SmbConstants.TYPE_FILESYSTEM,
                        e.getAttributes(),
                        e.createTime(),
                        e.lastModified(),
                        e.lastAccess(),
                        e.length()) ) {

                        if ( ff != null && ff.accept(f) == false ) {
                            continue;
                        }
                        if ( files ) {
                            list.add(f);
                        }
                        else {
                            list.add(name);
                        }
                    }
                }
            }

            if ( resp.isEndOfSearch || resp.numEntries == 0 ) {
                break;
            }

            req.reset(resp.resumeKey, resp.lastName);
            resp.reset();
            th.send(req, resp);
        }

        try {
            th.send(new SmbComFindClose2(th.getConfig(), sid), new SmbComBlankResponse(th.getConfig()));
        }
        catch ( SmbException se ) {
            log.debug("SmbComFindClose2 failed", se);
        }
    }


    static void doShareEnum ( SmbFile parent, List<Object> list, boolean files, String wildcard, int searchAttributes, SmbFilenameFilter fnf,
            SmbFileFilter ff ) throws CIFSException, MalformedURLException {
        // clone the locator so that the address index is not modified
        SmbResourceLocatorImpl locator = parent.fileLocator.clone();
        CIFSContext tc = parent.getContext();
        URL u = locator.getURL();

        IOException last = null;
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
                entries = doDfsRootEnum(tc, locator);
                for ( int ei = 0; ei < entries.length; ei++ ) {
                    FileEntry e = entries[ ei ];
                    if ( set.contains(e) == false )
                        set.add(e);
                }
            }
            catch ( IOException ioe ) {
                log.debug("DS enumeration failed", ioe);
            }
        }

        SmbTreeConnection treeConn = new SmbTreeConnection(tc);
        Address addr = locator.getFirstAddress();
        while ( addr != null ) {
            try ( SmbTreeHandleImpl th = treeConn.connectHost(locator, addr) ) {
                try {
                    entries = doMsrpcShareEnum(tc, locator.getURL().getHost(), addr);
                }
                catch ( IOException ioe ) {
                    log.debug("doMsrpcShareEnum failed", ioe);
                    entries = doNetShareEnum(th);
                }
                for ( int ei = 0; ei < entries.length; ei++ ) {
                    FileEntry e = entries[ ei ];
                    if ( set.contains(e) == false )
                        set.add(e);
                }
                break;
            }
            catch ( IOException ioe ) {
                log.debug("doNetShareEnum failed", ioe);
                last = ioe;
            }
            addr = locator.getNextAddress();
        }

        if ( last != null && set.isEmpty() ) {
            if ( ! ( last instanceof SmbException ) )
                throw new SmbException(u.toString(), last);
            throw (SmbException) last;
        }

        for ( FileEntry e : set ) {
            String name = e.getName();
            if ( fnf != null && fnf.accept(parent, name) == false )
                continue;
            if ( name.length() > 0 ) {
                // if !files we don't need to create SmbFiles here
                try ( SmbFile f = new SmbFile(
                    parent,
                    name,
                    false,
                    e.getType(),
                    SmbConstants.ATTR_READONLY | SmbConstants.ATTR_DIRECTORY,
                    0L,
                    0L,
                    0L,
                    0L) ) {
                    if ( ff != null && ff.accept(f) == false )
                        continue;
                    if ( files ) {
                        list.add(f);
                    }
                    else {
                        list.add(name);
                    }
                }
            }
        }
    }


    static List<Object> doEnum ( SmbFile parent, boolean files, String wildcard, int searchAttributes, SmbFilenameFilter fnf, SmbFileFilter ff )
            throws CIFSException {
        List<Object> list = new ArrayList<>();
        if ( ff != null && ff instanceof DosFileFilter ) {
            DosFileFilter dff = (DosFileFilter) ff;
            if ( dff.wildcard != null )
                wildcard = dff.wildcard;
            searchAttributes = dff.attributes;
        }
        SmbResourceLocatorImpl locator = parent.fileLocator;
        try {
            if ( locator.getURL().getHost().isEmpty() || locator.getType() == SmbConstants.TYPE_WORKGROUP ) {

                try ( SmbTreeHandleImpl th = parent.ensureTreeConnected() ) {
                    doNetServerEnum(parent, th, list, files, wildcard, searchAttributes, fnf, ff);
                }
            }
            else if ( locator.isRoot() ) {
                doShareEnum(parent, list, files, wildcard, searchAttributes, fnf, ff);
            }
            else {
                try ( SmbTreeHandleImpl th = parent.ensureTreeConnected() ) {
                    doFindFirstNext(parent, th, list, files, wildcard, searchAttributes, fnf, ff);
                }
            }

            return list;
        }
        catch ( MalformedURLException mue ) {
            throw new SmbException(locator.getURL().toString(), mue);
        }
    }

}
