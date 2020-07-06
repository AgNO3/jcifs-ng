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
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Locale;
import java.util.Objects;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.DfsReferralData;
import jcifs.RuntimeCIFSException;
import jcifs.SmbConstants;
import jcifs.SmbResourceLocator;
import jcifs.SmbTreeHandle;
import jcifs.internal.CommonServerMessageBlockRequest;
import jcifs.internal.CommonServerMessageBlockResponse;
import jcifs.internal.RequestWithPath;
import jcifs.internal.dfs.DfsReferralDataInternal;
import jcifs.internal.smb1.com.SmbComClose;
import jcifs.internal.smb1.com.SmbComFindClose2;
import jcifs.internal.smb1.trans.nt.NtTransQuerySecurityDesc;
import jcifs.util.transport.TransportException;


/**
 * This class encapsulates the logic for switching tree connections
 * 
 * Switching trees can occur either when the tree has been disconnected by failure or idle-timeout - as well as on
 * DFS referrals.
 * 
 * @author mbechler
 *
 */
class SmbTreeConnection {

    private static final Logger log = LoggerFactory.getLogger(SmbTreeConnection.class);

    private final CIFSContext ctx;
    private final SmbTreeConnection delegate;
    private SmbTreeImpl tree;
    private volatile boolean treeAcquired;
    private volatile boolean delegateAcquired;

    private SmbTransportInternal exclusiveTransport;
    private boolean nonPooled;

    private final AtomicLong usageCount = new AtomicLong();

    private static final Random RAND = new Random();


    protected SmbTreeConnection ( CIFSContext ctx ) {
        this.ctx = ctx;
        this.delegate = null;
    }


    protected SmbTreeConnection ( SmbTreeConnection treeConnection ) {
        this.ctx = treeConnection.ctx;
        this.delegate = treeConnection;
    }


    static SmbTreeConnection create ( CIFSContext c ) {
        if ( c.getConfig().isTraceResourceUsage() ) {
            return new SmbTreeConnectionTrace(c);
        }
        return new SmbTreeConnection(c);
    }


    static SmbTreeConnection create ( SmbTreeConnection c ) {
        if ( c.ctx.getConfig().isTraceResourceUsage() ) {
            return new SmbTreeConnectionTrace(c);
        }
        return new SmbTreeConnection(c);
    }


    /**
     * @return the active configuration
     */
    public Configuration getConfig () {
        return this.ctx.getConfig();
    }


    private synchronized SmbTreeImpl getTree () {
        SmbTreeImpl t = this.tree;
        if ( t != null ) {
            return t.acquire(false);
        }
        else if ( this.delegate != null ) {
            this.tree = this.delegate.getTree();
            return this.tree;
        }
        return t;
    }


    /**
     * @return
     */
    private synchronized SmbTreeImpl getTreeInternal () {
        SmbTreeImpl t = this.tree;
        if ( t != null ) {
            return t;
        }
        if ( this.delegate != null ) {
            return this.delegate.getTreeInternal();
        }
        return null;
    }


    /**
     * @param t
     */
    private synchronized void switchTree ( SmbTreeImpl t ) {
        try ( SmbTreeImpl old = getTree() ) {
            if ( old == t ) {
                return;
            }
            boolean wasAcquired = this.treeAcquired;
            log.debug("Switching tree");
            if ( t != null ) {
                log.debug("Acquired tree on switch " + t);
                t.acquire();
                this.treeAcquired = true;
            }
            else {
                this.treeAcquired = false;
            }

            this.tree = t;
            if ( old != null ) {
                if ( wasAcquired ) {
                    // release
                    old.release(true);
                }
            }
            if ( this.delegate != null && this.delegateAcquired ) {
                log.debug("Releasing delegate");
                this.delegateAcquired = false;
                this.delegate.release();
            }
        }
    }


    /**
     * @return tree connection with increased usage count
     */
    public SmbTreeConnection acquire () {
        long usage = this.usageCount.incrementAndGet();
        if ( log.isTraceEnabled() ) {
            log.trace("Acquire tree connection " + usage + " " + this);
        }

        if ( usage == 1 ) {
            synchronized ( this ) {
                try ( SmbTreeImpl t = getTree() ) {
                    if ( t != null ) {
                        if ( !this.treeAcquired ) {
                            if ( log.isDebugEnabled() ) {
                                log.debug("Acquire tree on first usage " + t);
                            }
                            t.acquire();
                            this.treeAcquired = true;
                        }
                    }
                }
                if ( this.delegate != null && !this.delegateAcquired ) {
                    log.debug("Acquire delegate on first usage");
                    this.delegate.acquire();
                    this.delegateAcquired = true;
                }
            }
        }

        return this;

    }


    /**
     * 
     */
    public void release () {
        long usage = this.usageCount.decrementAndGet();
        if ( log.isTraceEnabled() ) {
            log.trace("Release tree connection " + usage + " " + this);
        }

        if ( usage == 0 ) {
            synchronized ( this ) {
                try ( SmbTreeImpl t = getTree() ) {
                    if ( this.treeAcquired && t != null ) {
                        if ( log.isDebugEnabled() ) {
                            log.debug("Tree connection no longer in use, release tree " + t);
                        }
                        this.treeAcquired = false;
                        t.release();
                    }
                }
                if ( this.delegate != null && this.delegateAcquired ) {
                    this.delegateAcquired = false;
                    this.delegate.release();
                }
            }

            SmbTransportInternal et = this.exclusiveTransport;
            if ( et != null ) {
                synchronized ( this ) {
                    try {
                        log.debug("Disconnecting exclusive transport");
                        this.exclusiveTransport = null;
                        this.tree = null;
                        this.treeAcquired = false;
                        et.close();
                        et.disconnect(false, false);
                    }
                    catch ( Exception e ) {
                        log.error("Failed to close exclusive transport", e);
                    }
                }
            }
        }
        else if ( usage < 0 ) {
            log.error("Usage count dropped below zero " + this);
            throw new RuntimeCIFSException("Usage count dropped below zero");
        }
    }


    protected void checkRelease () {
        if ( isConnected() && this.usageCount.get() != 0 ) {
            log.warn("Tree connection was not properly released " + this);
        }
    }


    synchronized void disconnect ( boolean inError ) {
        try ( SmbSessionImpl session = getSession() ) {
            if ( session == null ) {
                return;
            }
            try ( SmbTransportImpl transport = session.getTransport() ) {
                synchronized ( transport ) {
                    SmbTreeImpl t = getTreeInternal();
                    if ( t != null ) {
                        try {
                            t.treeDisconnect(inError, true);
                        }
                        finally {
                            this.tree = null;
                            this.treeAcquired = false;
                        }
                    }
                    else {
                        this.delegate.disconnect(inError);
                    }
                }
            }
        }
    }


    <T extends CommonServerMessageBlockResponse> T send ( SmbResourceLocatorImpl loc, CommonServerMessageBlockRequest request, T response,
            RequestParam... params ) throws CIFSException {
        return send(loc, request, response, params.length == 0 ? EnumSet.noneOf(RequestParam.class) : EnumSet.copyOf(Arrays.asList(params)));
    }


    <T extends CommonServerMessageBlockResponse> T send ( SmbResourceLocatorImpl loc, CommonServerMessageBlockRequest request, T response,
            Set<RequestParam> params ) throws CIFSException {
        CIFSException last = null;
        RequestWithPath rpath = ( request instanceof RequestWithPath ) ? (RequestWithPath) request : null;
        String savedPath = rpath != null ? rpath.getPath() : null;
        String savedFullPath = rpath != null ? rpath.getFullUNCPath() : null;

        String fullPath = "\\" + loc.getServer() + "\\" + loc.getShare() + loc.getUNCPath();
        int maxRetries = this.ctx.getConfig().getMaxRequestRetries();
        for ( int retries = 1; retries <= maxRetries; retries++ ) {

            if ( rpath != null ) {
                rpath.setFullUNCPath(null, null, fullPath);
            }

            try {
                return send0(loc, request, response, params);
            }
            catch ( SmbException smbe ) {
                // Retrying only makes sense if the invalid parameter is an tree id. If we have a stale file descriptor
                // retrying make no sense, as it will never become available again.
                if ( params.contains(RequestParam.NO_RETRY)
                        || ( ! ( smbe.getCause() instanceof TransportException ) ) && smbe.getNtStatus() != NtStatus.NT_STATUS_INVALID_PARAMETER ) {
                    log.debug("Not retrying", smbe);
                    throw smbe;
                }
                log.debug("send", smbe);
                last = smbe;
            }
            catch ( CIFSException e ) {
                log.debug("send", e);
                last = e;
            }
            // If we get here, we got the 'The Parameter is incorrect' error or a transport exception
            // Disconnect and try again from scratch.

            if ( log.isDebugEnabled() ) {
                log.debug(String.format("Retrying (%d/%d) request %s", retries, maxRetries, request));
            }

            // should we disconnect the transport here? otherwise we make an additional attempt to detect that if the
            // server closed the connection as a result
            log.debug("Disconnecting tree on send retry", last);
            disconnect(true);

            if ( retries >= maxRetries ) {
                break;
            }

            try {
                if ( retries != 1 ) {
                    // backoff, but don't delay the first attempt as there are various reasons that can be fixed
                    // immediately
                    Thread.sleep(500 + RAND.nextInt(1000));
                }
            }
            catch ( InterruptedException e ) {
                log.debug("interrupted sleep in send", e);
            }

            if ( request != null ) {
                log.debug("Restting request");
                request.reset();
            }
            if ( rpath != null ) {
                // resolveDfs() and tree.send() modify the request packet.
                // I want to restore it before retrying. request.reset()
                // restores almost everything that was modified, except the path.
                rpath.setPath(savedPath);
                rpath.setFullUNCPath(rpath.getDomain(), rpath.getServer(), savedFullPath);
            }
            if ( response != null ) {
                response.reset();
            }

            try ( SmbTreeHandle th = connectWrapException(loc) ) {
                log.debug("Have new tree connection for retry");
            }
            catch ( SmbException e ) {
                log.debug("Failed to connect tree on retry", e);
                last = e;
            }
        }

        if ( last != null ) {
            log.debug("All attempts have failed, last exception", last);
            throw last;
        }
        throw new SmbException("All attempts failed, but no exception");
    }


    private <T extends CommonServerMessageBlockResponse> T send0 ( SmbResourceLocatorImpl loc, CommonServerMessageBlockRequest request, T response,
            Set<RequestParam> params ) throws CIFSException, DfsReferral {
        for ( int limit = 10; limit > 0; limit-- ) {
            if ( request instanceof RequestWithPath ) {
                ensureDFSResolved(loc, (RequestWithPath) request);
            }
            try ( SmbTreeImpl t = getTree() ) {
                if ( t == null ) {
                    throw new CIFSException("Failed to get tree connection");
                } ;
                return t.send(request, response, params);
            }
            catch ( DfsReferral dre ) {
                if ( dre.getData().unwrap(DfsReferralDataInternal.class).isResolveHashes() ) {
                    throw dre;
                }
                request.reset();
                log.trace("send0", dre);
            }
        }

        throw new CIFSException("Loop in DFS referrals");
    }


    /**
     * @param loc
     * @return tree handle
     * @throws SmbException
     */
    public SmbTreeHandleImpl connectWrapException ( SmbResourceLocatorImpl loc ) throws SmbException {
        try {
            return connect(loc);
        }
        catch ( UnknownHostException uhe ) {
            throw new SmbException("Failed to connect to server", uhe);
        }
        catch ( SmbException se ) {
            throw se;
        }
        catch ( IOException ioe ) {
            throw new SmbException("Failed to connect to server", ioe);
        }
    }


    /**
     * @param loc
     * @return tree handle
     * @throws IOException
     */
    public synchronized SmbTreeHandleImpl connect ( SmbResourceLocatorImpl loc ) throws IOException {
        try ( SmbSessionImpl session = getSession() ) {
            if ( isConnected() ) {
                try ( SmbTransportImpl transport = session.getTransport() ) {
                    if ( transport.isDisconnected() || transport.getRemoteHostName() == null ) {
                        /*
                         * Tree/session thinks it is connected but transport disconnected
                         * under it, reset tree to reflect the truth.
                         */
                        log.debug("Disconnecting failed tree and session");
                        disconnect(true);
                    }
                }
            }

            if ( isConnected() ) {
                log.trace("Already connected");
                return new SmbTreeHandleImpl(loc, this);
            }

            return connectHost(loc, loc.getServerWithDfs());
        }

    }


    /**
     * @return whether we have a valid tree connection
     */
    @SuppressWarnings ( "resource" )
    public synchronized boolean isConnected () {
        SmbTreeImpl t = getTreeInternal();
        return t != null && t.isConnected();
    }


    /**
     * 
     * @param loc
     * @param host
     * @return tree handle
     * @throws IOException
     */
    public synchronized SmbTreeHandleImpl connectHost ( SmbResourceLocatorImpl loc, String host ) throws IOException {
        return connectHost(loc, host, null);
    }


    /**
     * 
     * @param loc
     * @param host
     * @param referral
     * @return tree handle
     * @throws IOException
     */
    public synchronized SmbTreeHandleImpl connectHost ( SmbResourceLocatorImpl loc, String host, DfsReferralData referral ) throws IOException {
        String targetDomain = null;
        try ( SmbTreeImpl t = getTree() ) {
            if ( t != null ) {
                if ( log.isDebugEnabled() ) {
                    log.debug("Tree is " + t);
                }

                if ( Objects.equals(loc.getShare(), t.getShare()) ) {
                    try ( SmbSessionImpl session = t.getSession() ) {
                        targetDomain = session.getTargetDomain();
                        if ( !session.isFailed() ) {
                            try ( SmbTransportImpl trans = session.getTransport();
                                  SmbTreeImpl ct = connectTree(loc, host, t.getShare(), trans, t, null) ) {
                                switchTree(ct);
                                return new SmbTreeHandleImpl(loc, this);
                            }
                        }
                        log.debug("Session no longer valid");
                    }
                }
            }
        }

        String hostName = loc.getServerWithDfs();
        String path = ( loc.getType() == SmbConstants.TYPE_SHARE || loc.getUNCPath() == null || "\\".equals(loc.getUNCPath()) ) ? null
                : loc.getUNCPath();
        String share = loc.getShare();

        DfsReferralData start = referral != null ? referral : this.ctx.getDfs().resolve(this.ctx, hostName, loc.getShare(), path);
        DfsReferralData dr = start;
        IOException last = null;
        do {
            if ( dr != null ) {
                targetDomain = dr.getDomain();
                host = dr.getServer().toLowerCase(Locale.ROOT);
                share = dr.getShare();
            }

            try {

                if ( this.nonPooled ) {
                    if ( log.isDebugEnabled() ) {
                        log.debug("Using exclusive transport for " + this);
                    }
                    this.exclusiveTransport = this.ctx.getTransportPool()
                            .getSmbTransport(this.ctx, host, loc.getPort(), true, loc.shouldForceSigning()).unwrap(SmbTransportInternal.class);
                    SmbTransportInternal trans = this.exclusiveTransport;
                    try ( SmbSessionInternal smbSession = trans.getSmbSession(this.ctx, host, targetDomain).unwrap(SmbSessionInternal.class);
                          SmbTreeImpl uct = smbSession.getSmbTree(share, null).unwrap(SmbTreeImpl.class);
                          SmbTreeImpl ct = connectTree(loc, host, share, trans, uct, dr) ) {

                        if ( dr != null ) {
                            ct.setTreeReferral(dr);
                            if ( dr != start ) {
                                dr.unwrap(DfsReferralDataInternal.class).replaceCache();
                            }
                        }
                        switchTree(ct);
                        return new SmbTreeHandleImpl(loc, this);
                    }
                }

                try ( SmbTransportInternal trans = this.ctx.getTransportPool()
                        .getSmbTransport(this.ctx, host, loc.getPort(), false, loc.shouldForceSigning()).unwrap(SmbTransportInternal.class);
                      SmbSessionInternal smbSession = trans.getSmbSession(this.ctx, host, targetDomain).unwrap(SmbSessionInternal.class);
                      SmbTreeImpl uct = smbSession.getSmbTree(share, null).unwrap(SmbTreeImpl.class);
                      SmbTreeImpl ct = connectTree(loc, host, share, trans, uct, dr) ) {
                    if ( dr != null ) {
                        ct.setTreeReferral(dr);
                        if ( dr != start ) {
                            dr.unwrap(DfsReferralDataInternal.class).replaceCache();
                        }
                    }
                    switchTree(ct);
                    return new SmbTreeHandleImpl(loc, this);
                }
            }
            catch ( IOException e ) {
                last = e;
                log.debug("Referral failed, trying next", e);
            }

            if ( dr != null ) {
                dr = dr.next();
            }
        }
        while ( dr != start );
        throw last;
    }


    /**
     * @param loc
     * @param addr
     * @param trans
     * @param t
     * @throws CIFSException
     */
    private SmbTreeImpl connectTree ( SmbResourceLocatorImpl loc, String addr, String share, SmbTransportInternal trans, SmbTreeImpl t,
            DfsReferralData referral ) throws CIFSException {
        if ( log.isDebugEnabled() && trans.isSigningOptional() && !loc.isIPC() && !this.ctx.getConfig().isSigningEnforced() ) {
            log.debug("Signatures for file enabled but not required " + this);
        }

        if ( referral != null ) {
            t.markDomainDfs();
        }

        try {
            if ( log.isTraceEnabled() ) {
                log.trace("doConnect: " + addr);
            }
            t.treeConnect(null, null);
            return t.acquire();
        }
        catch ( SmbAuthException sae ) {
            log.debug("Authentication failed", sae);
            return retryAuthentication(loc, share, trans, t, referral, sae);
        }
    }


    private SmbTreeImpl retryAuthentication ( SmbResourceLocatorImpl loc, String share, SmbTransportInternal trans, SmbTreeImpl t,
            DfsReferralData referral, SmbAuthException sae ) throws SmbAuthException, CIFSException {
        try ( SmbSessionImpl treesess = t.getSession() ) {
            if ( treesess.getCredentials().isAnonymous() || treesess.getCredentials().isGuest() ) {
                // refresh anonymous session or fallback to anonymous from guest login
                try ( SmbSessionInternal s = trans
                        .getSmbSession(this.ctx.withAnonymousCredentials(), treesess.getTargetHost(), treesess.getTargetDomain())
                        .unwrap(SmbSessionInternal.class);
                      SmbTreeImpl tr = s.getSmbTree(share, null).unwrap(SmbTreeImpl.class) ) {
                    tr.treeConnect(null, null);
                    log.debug("Anonymous retry succeeded");
                    return tr.acquire();
                }
                catch ( Exception e ) {
                    log.debug("Retry also failed", e);
                    throw sae;
                }
            }
            else if ( this.ctx.renewCredentials(loc.getURL().toString(), sae) ) {
                log.debug("Trying to renew credentials after auth error");
                try ( SmbSessionInternal s = trans.getSmbSession(this.ctx, treesess.getTargetHost(), treesess.getTargetDomain())
                        .unwrap(SmbSessionInternal.class);
                      SmbTreeImpl tr = s.getSmbTree(share, null).unwrap(SmbTreeImpl.class) ) {
                    if ( referral != null ) {
                        tr.markDomainDfs();
                    }
                    tr.treeConnect(null, null);
                    return tr.acquire();
                }
            }
            else {
                throw sae;
            }
        }
    }


    SmbResourceLocator ensureDFSResolved ( SmbResourceLocatorImpl loc ) throws CIFSException {
        return ensureDFSResolved(loc, null);
    }


    SmbResourceLocator ensureDFSResolved ( SmbResourceLocatorImpl loc, RequestWithPath request ) throws CIFSException {
        if ( request instanceof SmbComClose )
            return loc;

        for ( int retries = 0; retries < 1 + this.ctx.getConfig().getMaxRequestRetries(); retries++ ) {
            try {
                return resolveDfs0(loc, request);
            }
            catch ( SmbException smbe ) {
                // The connection may have been dropped?
                if ( smbe.getNtStatus() != NtStatus.NT_STATUS_NOT_FOUND && ! ( smbe.getCause() instanceof TransportException ) ) {
                    throw smbe;
                }
                log.debug("resolveDfs", smbe);
            }
            // If we get here, we apparently have a bad connection.
            // Disconnect and try again.
            if ( log.isDebugEnabled() ) {
                log.debug("Retrying (" + retries + ") resolveDfs: " + request);
            }
            log.debug("Disconnecting tree on DFS retry");
            disconnect(true);
            try {
                Thread.sleep(500 + RAND.nextInt(5000));
            }
            catch ( InterruptedException e ) {
                log.debug("resolveDfs", e);
            }

            try ( SmbTreeHandle th = connectWrapException(loc) ) {}
        }

        return loc;
    }


    private SmbResourceLocator resolveDfs0 ( SmbResourceLocatorImpl loc, RequestWithPath request ) throws CIFSException {
        try ( SmbTreeHandleImpl th = connectWrapException(loc);
              SmbSessionImpl session = th.getSession();
              SmbTransportImpl transport = session.getTransport();
              SmbTreeImpl t = getTree() ) {
            transport.ensureConnected();

            String rpath = request != null ? request.getPath() : loc.getUNCPath();
            String rfullpath = request != null ? request.getFullUNCPath() : ( '\\' + loc.getServer() + '\\' + loc.getShare() + loc.getUNCPath() );
            if ( t.isInDomainDfs() || !t.isPossiblyDfs() ) {
                if ( t.isInDomainDfs() ) {
                    // need to adjust request path
                    DfsReferralData dr = t.getTreeReferral();
                    if ( dr != null ) {
                        if ( log.isDebugEnabled() ) {
                            log.debug(String.format("Need to adjust request path %s (full: %s) -> %s", rpath, rfullpath, dr));
                        }
                        String dunc = loc.handleDFSReferral(dr, rpath);
                        if ( request != null ) {
                            request.setPath(dunc);
                        }
                        return loc;
                    }

                    // fallthrough to normal handling
                    log.debug("No tree referral but in DFS");
                }
                else {
                    log.trace("Not in DFS");
                    return loc;
                }
            }

            if ( request != null ) {
                request.setFullUNCPath(session.getTargetDomain(), session.getTargetHost(), rfullpath);
            }

            // for standalone DFS we could be checking for a referral here, too
            DfsReferralData dr = this.ctx.getDfs().resolve(this.ctx, loc.getServer(), loc.getShare(), loc.getUNCPath());
            if ( dr != null ) {
                if ( log.isDebugEnabled() ) {
                    log.debug("Resolved " + rfullpath + " -> " + dr);
                }

                String dunc = loc.handleDFSReferral(dr, rpath);
                if ( request != null ) {
                    request.setPath(dunc);
                }

                if ( !t.getShare().equals(dr.getShare()) ) {
                    // this should only happen for standalone roots or if the DC/domain root lookup failed
                    IOException last;
                    DfsReferralData start = dr;
                    do {
                        if ( log.isDebugEnabled() ) {
                            log.debug("Need to switch tree for " + dr);
                        }
                        try ( SmbTreeHandleImpl nt = connectHost(loc, session.getTargetHost(), dr) ) {
                            log.debug("Switched tree");
                            return loc;
                        }
                        catch ( IOException e ) {
                            log.debug("Failed to connect tree", e);
                            last = e;
                        }
                        dr = dr.next();
                    }
                    while ( dr != start );
                    throw new CIFSException("All referral tree connections failed", last);
                }

                return loc;
            }
            else if ( t.isInDomainDfs() && ! ( request instanceof NtTransQuerySecurityDesc ) && ! ( request instanceof SmbComClose )
                    && ! ( request instanceof SmbComFindClose2 ) ) {
                if ( log.isDebugEnabled() ) {
                    log.debug("No referral available for  " + rfullpath);
                }
                throw new CIFSException("No referral but in domain DFS " + rfullpath);
            }
            else {
                log.trace("Not in DFS");
                return loc;
            }
        }
    }


    /**
     * Use a exclusive connection for this tree
     * 
     * If an exclusive connection is used the caller must make sure that the tree handle is kept alive,
     * otherwise the connection will be disconnected once the usage drops to zero.
     * 
     * @param np
     *            whether to use an exclusive connection
     */
    void setNonPooled ( boolean np ) {
        this.nonPooled = np;
    }


    /**
     * @return the currently connected tid
     */
    @SuppressWarnings ( "resource" )
    public long getTreeId () {
        SmbTreeImpl t = getTreeInternal();
        if ( t == null ) {
            return -1;
        }
        return t.getTreeNum();
    }


    /**
     * 
     * Only call this method while holding a tree handle
     * 
     * @return session that this file has been loaded through
     */
    @SuppressWarnings ( "resource" )
    public SmbSessionImpl getSession () {
        SmbTreeImpl t = getTreeInternal();
        if ( t != null ) {
            return t.getSession();
        }
        return null;
    }


    /**
     * 
     * Only call this method while holding a tree handle
     * 
     * @param cap
     * @return whether the capability is available
     * @throws SmbException
     */
    public boolean hasCapability ( int cap ) throws SmbException {
        try ( SmbSessionImpl s = getSession() ) {
            if ( s != null ) {
                try ( SmbTransportImpl transport = s.getTransport() ) {
                    return transport.hasCapability(cap);
                }
            }
            throw new SmbException("Not connected");
        }
    }


    /**
     * Only call this method while holding a tree handle
     * 
     * @return the connected tree type
     */
    public int getTreeType () {
        try ( SmbTreeImpl t = getTree() ) {
            return t.getTreeType();
        }
    }


    /**
     * 
     * Only call this method while holding a tree handle
     * 
     * @return the share we are connected to
     */
    public String getConnectedShare () {
        try ( SmbTreeImpl t = getTree() ) {
            return t.getShare();
        }
    }


    /**
     * 
     * Only call this method while holding a tree handle
     * 
     * @param other
     * @return whether the connection refers to the same tree
     */
    public boolean isSame ( SmbTreeConnection other ) {
        try ( SmbTreeImpl t1 = getTree();
              SmbTreeImpl t2 = other.getTree() ) {
            return t1 == t2;
        }
    }

}
