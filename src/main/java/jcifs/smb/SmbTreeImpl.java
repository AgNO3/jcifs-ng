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
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.DfsReferralData;
import jcifs.DialectVersion;
import jcifs.RuntimeCIFSException;
import jcifs.SmbConstants;
import jcifs.SmbTree;
import jcifs.internal.CommonServerMessageBlockRequest;
import jcifs.internal.CommonServerMessageBlockResponse;
import jcifs.internal.RequestWithPath;
import jcifs.internal.SmbNegotiationResponse;
import jcifs.internal.TreeConnectResponse;
import jcifs.internal.smb1.ServerMessageBlock;
import jcifs.internal.smb1.com.SmbComBlankResponse;
import jcifs.internal.smb1.com.SmbComNegotiateResponse;
import jcifs.internal.smb1.com.SmbComTreeConnectAndX;
import jcifs.internal.smb1.com.SmbComTreeConnectAndXResponse;
import jcifs.internal.smb1.com.SmbComTreeDisconnect;
import jcifs.internal.smb1.trans.SmbComTransaction;
import jcifs.internal.smb1.trans2.Trans2FindFirst2;
import jcifs.internal.smb1.trans2.Trans2FindFirst2Response;
import jcifs.internal.smb2.ServerMessageBlock2;
import jcifs.internal.smb2.ioctl.Smb2IoctlRequest;
import jcifs.internal.smb2.ioctl.Smb2IoctlResponse;
import jcifs.internal.smb2.ioctl.ValidateNegotiateInfoRequest;
import jcifs.internal.smb2.ioctl.ValidateNegotiateInfoResponse;
import jcifs.internal.smb2.nego.Smb2NegotiateRequest;
import jcifs.internal.smb2.nego.Smb2NegotiateResponse;
import jcifs.internal.smb2.tree.Smb2TreeConnectRequest;
import jcifs.internal.smb2.tree.Smb2TreeDisconnectRequest;


class SmbTreeImpl implements SmbTreeInternal {

    private static final Logger log = LoggerFactory.getLogger(SmbTreeImpl.class);

    private static AtomicLong TREE_CONN_COUNTER = new AtomicLong();

    /*
     * 0 - not connected
     * 1 - connecting
     * 2 - connected
     * 3 - disconnecting
     */
    private final AtomicInteger connectionState = new AtomicInteger();

    private final String share;
    private final String service0;
    private final SmbSessionImpl session;

    private volatile int tid = -1;
    private volatile String service = "?????";
    private volatile boolean inDfs, inDomainDfs;
    private volatile long treeNum; // used by SmbFile.isOpen

    private final AtomicLong usageCount = new AtomicLong(0);
    private final AtomicBoolean sessionAcquired = new AtomicBoolean(true);

    private final boolean traceResource;
    private final List<StackTraceElement[]> acquires;
    private final List<StackTraceElement[]> releases;

    SmbTreeImpl ( SmbSessionImpl session, String share, String service ) {
        this.session = session.acquire();
        this.share = share.toUpperCase();
        if ( service != null && !service.startsWith("??") ) {
            this.service = service;
        }
        this.service0 = this.service;

        this.traceResource = this.session.getConfig().isTraceResourceUsage();
        if ( this.traceResource ) {
            this.acquires = new LinkedList<>();
            this.releases = new LinkedList<>();
        }
        else {
            this.acquires = null;
            this.releases = null;
        }
    }


    boolean matches ( String shr, String servc ) {
        return this.share.equalsIgnoreCase(shr) && ( servc == null || servc.startsWith("??") || this.service.equalsIgnoreCase(servc) );
    }


    @Override
    public boolean equals ( Object obj ) {
        if ( obj instanceof SmbTreeImpl ) {
            SmbTreeImpl tree = (SmbTreeImpl) obj;
            return matches(tree.share, tree.service);
        }
        return false;
    }


    public SmbTreeImpl acquire () {
        return acquire(true);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.SmbTree#unwrap(java.lang.Class)
     */
    @SuppressWarnings ( "unchecked" )
    @Override
    public <T extends SmbTree> T unwrap ( Class<T> type ) {
        if ( type.isAssignableFrom(this.getClass()) ) {
            return (T) this;
        }
        throw new ClassCastException();
    }


    /**
     * @param track
     * @return tree with increased usage count
     */
    public SmbTreeImpl acquire ( boolean track ) {
        long usage = this.usageCount.incrementAndGet();
        if ( log.isTraceEnabled() ) {
            log.trace("Acquire tree " + usage + " " + this);
        }

        if ( track && this.traceResource ) {
            synchronized ( this.acquires ) {
                this.acquires.add(truncateTrace(Thread.currentThread().getStackTrace()));
            }
        }

        if ( usage == 1 ) {
            synchronized ( this ) {
                if ( this.sessionAcquired.compareAndSet(false, true) ) {
                    log.debug("Reacquire session");
                    this.session.acquire();
                }
            }
        }
        return this;
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.AutoCloseable#close()
     */
    @Override
    public void close () {
        release(false);
    }


    public void release () {
        release(true);
    }


    /**
     * @param track
     */
    public void release ( boolean track ) {
        long usage = this.usageCount.decrementAndGet();
        if ( log.isTraceEnabled() ) {
            log.trace("Release tree " + usage + " " + this);
        }

        if ( track && this.traceResource ) {
            synchronized ( this.releases ) {
                this.releases.add(truncateTrace(Thread.currentThread().getStackTrace()));
            }
        }

        if ( usage == 0 ) {
            synchronized ( this ) {
                log.debug("Usage dropped to zero, release session");
                if ( this.sessionAcquired.compareAndSet(true, false) ) {
                    this.session.release();
                }
            }
        }
        else if ( usage < 0 ) {
            log.error("Usage count dropped below zero " + this);
            dumpResource();
            throw new RuntimeCIFSException("Usage count dropped below zero");
        }
    }


    /**
     * @param stackTrace
     * @return
     */
    private static StackTraceElement[] truncateTrace ( StackTraceElement[] stackTrace ) {

        int s = 2;
        int e = stackTrace.length;

        for ( int i = s; i < e; i++ ) {
            StackTraceElement se = stackTrace[ i ];

            if ( i == s && SmbTreeImpl.class.getName().equals(se.getClassName()) && "close".equals(se.getMethodName()) ) {
                s++;
                continue;
            }

            if ( se.getClassName().startsWith("org.junit.runners.") ) {
                e = i - 4;
                break;
            }
        }

        StackTraceElement[] res = new StackTraceElement[e - s];
        System.arraycopy(stackTrace, s, res, 0, e - s);
        return res;
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#finalize()
     */
    @Override
    protected void finalize () throws Throwable {
        if ( isConnected() && this.usageCount.get() != 0 ) {
            log.warn("Tree was not properly released");
        }
    }


    /**
     *
     * @return whether the tree is connected
     */
    public boolean isConnected () {
        return this.tid != -1 && this.session.isConnected() && this.connectionState.get() == 2;
    }


    /**
     * @return the type of this tree
     */
    public int getTreeType () {
        String connectedService = getService();
        if ( "LPT1:".equals(connectedService) ) {
            return SmbConstants.TYPE_PRINTER;
        }
        else if ( "COMM".equals(connectedService) ) {
            return SmbConstants.TYPE_COMM;
        }
        return SmbConstants.TYPE_SHARE;
    }


    /**
     * @return the service
     */
    public String getService () {
        return this.service;
    }


    /**
     * @return the share
     */
    public String getShare () {
        return this.share;
    }


    /**
     * @return whether this is a DFS share
     */
    public boolean isDfs () {
        return this.inDfs;
    }


    /**
     *
     */
    void markDomainDfs () {
        this.inDomainDfs = true;
    }


    /**
     * @return whether this tree was accessed using domain DFS
     */
    public boolean isInDomainDfs () {
        return this.inDomainDfs;
    }


    /**
     * @return whether this tree may be a DFS share
     * @throws SmbException
     */
    public boolean isPossiblyDfs () throws SmbException {
        if ( this.connectionState.get() == 2 ) {
            // we are connected, so we know
            return isDfs();
        }
        try ( SmbTransportImpl transport = this.session.getTransport() ) {
            return transport.getNegotiateResponse().isDFSSupported();
        }
    }


    /**
     * @return the session this tree is connected in
     */
    public SmbSessionImpl getSession () {
        return this.session.acquire();
    }


    /**
     * @return the tid
     */
    public int getTid () {
        return this.tid;
    }


    /**
     * @return the tree_num (monotonically increasing counter to track reconnects)
     */
    public long getTreeNum () {
        return this.treeNum;
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode () {
        return this.share.hashCode() + 7 * this.service.hashCode();
    }


    @Override
    public <T extends CommonServerMessageBlockResponse> T send ( jcifs.internal.Request<T> request, RequestParam... params ) throws CIFSException {
        return send(
            (CommonServerMessageBlockRequest) request,
            request.getResponse(),
            ( params != null && params.length > 0 ) ? EnumSet.copyOf(Arrays.asList(params)) : EnumSet.noneOf(RequestParam.class));
    }


    <T extends CommonServerMessageBlockResponse> T send ( CommonServerMessageBlockRequest request, T response ) throws CIFSException {
        return send(request, response, Collections.<RequestParam> emptySet());
    }


    <T extends CommonServerMessageBlockResponse> T send ( CommonServerMessageBlockRequest request, T response, Set<RequestParam> params )
            throws CIFSException {
        try ( SmbSessionImpl sess = getSession();
              SmbTransportImpl transport = sess.getTransport() ) {
            if ( response != null ) {
                response.clearReceived();
            }

            // try TreeConnectAndX with the request
            // this does not make any sense if we are disconnecting right now
            T chainedResponse = null;
            if ( ! ( request instanceof SmbComTreeDisconnect ) && ! ( request instanceof Smb2TreeDisconnectRequest ) ) {
                chainedResponse = treeConnect(request, response);
            }
            if ( request == null || ( chainedResponse != null && chainedResponse.isReceived() ) ) {
                return chainedResponse;
            }

            // fall trough if the tree connection is already established
            // and send it as a separate request instead
            String svc = null;
            int t = this.tid;
            request.setTid(t);

            if ( !transport.isSMB2() ) {
                ServerMessageBlock req = (ServerMessageBlock) request;
                svc = this.service;
                if ( svc == null ) {
                    // there still is some kind of race condition, where?
                    // this used to trigger "invalid operation..."
                    throw new SmbException("Service is null in state " + this.connectionState.get());
                }
                checkRequest(transport, req, svc);

            }

            if ( this.isDfs() && !"IPC".equals(svc) && !"IPC$".equals(this.share) && request instanceof RequestWithPath ) {
                /*
                 * When DFS is in action all request paths are
                 * full UNC paths minus the first backslash like
                 * \server\share\path\to\file
                 * as opposed to normally
                 * \path\to\file
                 */
                RequestWithPath preq = (RequestWithPath) request;
                if ( preq.getPath() != null && preq.getPath().length() > 0 ) {
                    if ( log.isDebugEnabled() ) {
                        log.debug(String.format("Setting DFS request path from %s to %s", preq.getPath(), preq.getFullUNCPath()));
                    }
                    preq.setResolveInDfs(true);
                    preq.setPath(preq.getFullUNCPath());
                }
            }

            try {
                return sess.send(request, response, params);
            }
            catch ( SmbException se ) {
                if ( se.getNtStatus() == NtStatus.NT_STATUS_NETWORK_NAME_DELETED ) {
                    /*
                     * Someone removed the share while we were
                     * connected. Bastards! Disconnect this tree
                     * so that it reconnects cleanly should the share
                     * reappear in this client's lifetime.
                     */
                    log.debug("Disconnect tree on NT_STATUS_NETWORK_NAME_DELETED");
                    treeDisconnect(true, true);
                }
                throw se;
            }
        }
    }


    /**
     * @param transport
     * @param request
     * @throws SmbException
     */
    private static void checkRequest ( SmbTransportImpl transport, ServerMessageBlock request, String svc ) throws SmbException {
        if ( !"A:".equals(svc) ) {
            switch ( request.getCommand() ) {
            case ServerMessageBlock.SMB_COM_OPEN_ANDX:
            case ServerMessageBlock.SMB_COM_NT_CREATE_ANDX:
            case ServerMessageBlock.SMB_COM_READ_ANDX:
            case ServerMessageBlock.SMB_COM_WRITE_ANDX:
            case ServerMessageBlock.SMB_COM_CLOSE:
            case ServerMessageBlock.SMB_COM_TREE_DISCONNECT:
                break;
            case ServerMessageBlock.SMB_COM_TRANSACTION:
            case ServerMessageBlock.SMB_COM_TRANSACTION2:
                switch ( ( (SmbComTransaction) request ).getSubCommand() & 0xFF ) {
                case SmbComTransaction.NET_SHARE_ENUM:
                case SmbComTransaction.NET_SERVER_ENUM2:
                case SmbComTransaction.NET_SERVER_ENUM3:
                case SmbComTransaction.TRANS_PEEK_NAMED_PIPE:
                case SmbComTransaction.TRANS_WAIT_NAMED_PIPE:
                case SmbComTransaction.TRANS_CALL_NAMED_PIPE:
                case SmbComTransaction.TRANS_TRANSACT_NAMED_PIPE:
                case SmbComTransaction.TRANS2_GET_DFS_REFERRAL:
                    break;
                default:
                    throw new SmbException("Invalid operation for " + svc + " service: " + request);
                }
                break;
            default:
                throw new SmbException("Invalid operation for " + svc + " service" + request);
            }
        }
    }


    @SuppressWarnings ( "unchecked" )
    <T extends CommonServerMessageBlockResponse> T treeConnect ( CommonServerMessageBlockRequest andx, T andxResponse ) throws CIFSException {
        CommonServerMessageBlockRequest request = null;
        TreeConnectResponse response = null;
        try ( SmbSessionImpl sess = getSession();
              SmbTransportImpl transport = sess.getTransport() ) {
            synchronized ( transport ) {

                // this needs to be done before the reference to the remote hostname later
                transport.ensureConnected();

                if ( waitForState(transport) == 2 ) {
                    // already connected
                    return null;
                }
                int before = this.connectionState.getAndSet(1);
                if ( before == 1 ) {
                    // concurrent connection attempt
                    if ( waitForState(transport) == 2 ) {
                        // finished connecting
                        return null;
                    }
                    // failure to connect
                    throw new SmbException("Tree disconnected while waiting for connection");
                }
                else if ( before == 2 ) {
                    // concurrently connected
                    return null;
                }

                if ( log.isDebugEnabled() ) {
                    log.debug("Connection state was " + before);
                }

                try {
                    /*
                     * The hostname to use in the path is only known for
                     * sure if the NetBIOS session has been successfully
                     * established.
                     */

                    String tconHostName = sess.getTargetHost();

                    if ( tconHostName == null ) {
                        throw new SmbException("Transport disconnected while waiting for connection");
                    }

                    SmbNegotiationResponse nego = transport.getNegotiateResponse();

                    String unc = "\\\\" + tconHostName + '\\' + this.share;

                    /*
                     * IBM iSeries doesn't like specifying a service. Always reset
                     * the service to whatever was determined in the constructor.
                     */
                    String svc = this.service0;

                    /*
                     * Tree Connect And X Request / Response
                     */

                    if ( log.isDebugEnabled() ) {
                        log.debug("treeConnect: unc=" + unc + ",service=" + svc);
                    }

                    if ( transport.isSMB2() ) {
                        Smb2TreeConnectRequest req = new Smb2TreeConnectRequest(sess.getConfig(), unc);
                        if ( andx != null ) {
                            req.chain((ServerMessageBlock2) andx);
                        }
                        request = req;
                    }
                    else {
                        response = new SmbComTreeConnectAndXResponse(sess.getConfig(), (ServerMessageBlock) andxResponse);
                        request = new SmbComTreeConnectAndX(
                            sess.getContext(),
                            ( (SmbComNegotiateResponse) nego ).getServerData(),
                            unc,
                            svc,
                            (ServerMessageBlock) andx);
                    }

                    response = sess.send(request, response);
                    treeConnected(transport, sess, response);

                    if ( andxResponse != null && andxResponse.isReceived() ) {
                        return andxResponse;
                    }
                    else if ( transport.isSMB2() ) {
                        return (T) response.getNextResponse();
                    }
                    return null;
                }
                catch ( IOException se ) {
                    if ( request != null && request.getResponse() != null ) {
                        // tree connect might still have succeeded
                        response = (TreeConnectResponse) request.getResponse();
                        if ( response.isReceived() && !response.isError() && response.getErrorCode() == NtStatus.NT_STATUS_OK ) {
                            if ( !transport.isDisconnected() ) {
                                treeConnected(transport, sess, response);
                            }
                            throw se;
                        }
                    }
                    try {
                        log.debug("Disconnect tree on treeConnectFailure", se);
                        treeDisconnect(true, true);
                    }
                    finally {
                        this.connectionState.set(0);
                    }
                    throw se;
                }
                finally {
                    transport.notifyAll();
                }
            }
        }
    }


    /**
     * @param transport
     * @param sess
     * @param response
     * @throws IOException
     */
    private void treeConnected ( SmbTransportImpl transport, SmbSessionImpl sess, TreeConnectResponse response ) throws CIFSException {
        if ( !response.isValidTid() ) {
            throw new SmbException("TreeID is invalid");
        }
        this.tid = response.getTid();
        String rsvc = response.getService();
        if ( rsvc == null && !transport.isSMB2() ) {
            throw new SmbException("Service is NULL");
        }

        if ( transport.getContext().getConfig().isIpcSigningEnforced() && ( "IPC$".equals(this.getShare()) || "IPC".equals(rsvc) )
                && !sess.getCredentials().isAnonymous() && sess.getDigest() == null ) {
            throw new SmbException("IPC signing is enforced, but no signing is available");
        }

        this.service = rsvc;
        this.inDfs = response.isShareDfs();
        this.treeNum = TREE_CONN_COUNTER.incrementAndGet();

        this.connectionState.set(2); // connected

        try {
            validateNegotiation(transport, sess);
        }
        catch ( CIFSException se ) {
            try {
                transport.disconnect(true);
            }
            catch ( IOException e ) {
                log.warn("Failed to disconnect transport", e);
                se.addSuppressed(e);
            }
            throw se;
        }
    }


    /**
     * @param trans
     * @param sess
     * @throws CIFSException
     *
     */
    private void validateNegotiation ( SmbTransportImpl trans, SmbSessionImpl sess ) throws CIFSException {
        if ( !trans.isSMB2() || trans.getDigest() == null || !sess.getConfig().isRequireSecureNegotiate() ) {
            log.debug("Secure negotiation does not apply");
            return;
        }

        Smb2NegotiateResponse nego = (Smb2NegotiateResponse) trans.getNegotiateResponse();
        if ( nego.getSelectedDialect().atLeast(DialectVersion.SMB311) ) {
            // have preauth integrity instead
            log.debug("Secure negotiation does not apply, is SMB3.1");
            return;
        }
        Smb2NegotiateRequest negoReq = new Smb2NegotiateRequest(sess.getConfig(), trans.getRequestSecurityMode(nego));

        log.debug("Sending VALIDATE_NEGOTIATE_INFO");
        Smb2IoctlRequest req = new Smb2IoctlRequest(sess.getConfig(), Smb2IoctlRequest.FSCTL_VALIDATE_NEGOTIATE_INFO);
        req.setFlags(Smb2IoctlRequest.SMB2_O_IOCTL_IS_FSCTL);
        req.setInputData(
            new ValidateNegotiateInfoRequest(
                negoReq.getCapabilities(),
                negoReq.getClientGuid(),
                (short) negoReq.getSecurityMode(),
                negoReq.getDialects()));

        Smb2IoctlResponse resp;
        try {
            resp = send(req, RequestParam.NO_RETRY);
        }
        catch ( SMBSignatureValidationException e ) {
            throw new SMBProtocolDowngradeException("Signature error during negotiate validation", e);
        }
        catch ( SmbException e ) {
            if ( log.isDebugEnabled() ) {
                log.debug(String.format("VALIDATE_NEGOTIATE_INFO response code 0x%x", e.getNtStatus()));
            }
            log.trace("VALIDATE_NEGOTIATE_INFO returned error", e);
            if ( ( req.getResponse().isReceived() && req.getResponse().isVerifyFailed() ) || e.getNtStatus() == NtStatus.NT_STATUS_ACCESS_DENIED ) {
                // this is the signature error
                throw new SMBProtocolDowngradeException("Signature error during negotiate validation", e);
            }

            // other errors are treated as success
            return;
        }
        ValidateNegotiateInfoResponse out = resp.getOutputData(ValidateNegotiateInfoResponse.class);

        if ( nego.getSecurityMode() != out.getSecurityMode() || nego.getCapabilities() != out.getCapabilities()
                || nego.getDialectRevision() != out.getDialect() || !Arrays.equals(nego.getServerGuid(), out.getServerGuid()) ) {
            log.debug("Secure negotiation failure");
            throw new CIFSException("Mismatched attributes validating negotiate info");
        }

        log.debug("Secure negotiation OK");
    }


    /**
     * @param transport
     * @return
     * @throws SmbException
     */
    private int waitForState ( SmbTransportImpl transport ) throws SmbException {
        int cs;
        while ( ( cs = this.connectionState.get() ) != 0 ) {
            if ( cs == 2 ) {
                return cs;
            }
            if ( cs == 3 ) {
                throw new SmbException("Disconnecting during tree connect");
            }
            try {
                log.debug("Waiting for transport");
                transport.wait();
            }
            catch ( InterruptedException ie ) {
                throw new SmbException(ie.getMessage(), ie);
            }
        }
        return cs;
    }


    /**
     *
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbTreeInternal#connectLogon(jcifs.CIFSContext)
     */
    @Override
    @Deprecated
    public void connectLogon ( CIFSContext tf ) throws SmbException {
        if ( tf.getConfig().getLogonShare() == null ) {
            try {
                treeConnect(null, null);
            }
            catch ( SmbException e ) {
                throw e;
            }
            catch ( CIFSException e ) {
                throw SmbException.wrap(e);
            }
        }
        else {
            Trans2FindFirst2 req = new Trans2FindFirst2(
                tf.getConfig(),
                "\\",
                "*",
                SmbConstants.ATTR_DIRECTORY,
                tf.getConfig().getListCount(),
                tf.getConfig().getListSize());
            Trans2FindFirst2Response resp = new Trans2FindFirst2Response(tf.getConfig());
            try {
                send(req, resp);
            }
            catch ( SmbException e ) {
                throw e;
            }
            catch ( CIFSException e ) {
                throw new SmbException("Logon share connection failed", e);
            }
        }
    }


    boolean treeDisconnect ( boolean inError, boolean inUse ) {
        boolean wasInUse = false;
        try ( SmbSessionImpl sess = getSession();
              SmbTransportImpl transport = sess.getTransport() ) {
            synchronized ( transport ) {
                int st = this.connectionState.getAndSet(3);
                if ( st == 2 ) {
                    long l = this.usageCount.get();
                    if ( ( inUse && l != 1 ) || ( !inUse && l > 0 ) ) {
                        log.warn("Disconnected tree while still in use " + this);
                        dumpResource();
                        wasInUse = true;
                        if ( sess.getConfig().isTraceResourceUsage() ) {
                            throw new RuntimeCIFSException("Disconnected tree while still in use");
                        }
                    }

                    if ( !inError && this.tid != -1 ) {
                        try {
                            if ( transport.isSMB2() ) {
                                Smb2TreeDisconnectRequest req = new Smb2TreeDisconnectRequest(sess.getConfig());
                                send(req.ignoreDisconnect());
                            }
                            else {
                                send(new SmbComTreeDisconnect(sess.getConfig()), new SmbComBlankResponse(sess.getConfig()));
                            }
                        }
                        catch ( CIFSException se ) {
                            log.error("Tree disconnect failed", se);
                        }
                    }
                }
                this.inDfs = false;
                this.inDomainDfs = false;
                this.connectionState.set(0);
                transport.notifyAll();
            }
        }
        return wasInUse;
    }


    /**
     *
     */
    private void dumpResource () {
        if ( !this.traceResource ) {
            return;
        }

        synchronized ( this.acquires ) {
            for ( StackTraceElement[] acq : this.acquires ) {
                log.debug("Acquire " + Arrays.toString(acq));
            }
        }

        synchronized ( this.releases ) {
            for ( StackTraceElement[] rel : this.releases ) {
                log.debug("Release " + Arrays.toString(rel));
            }
        }
    }


    @Override
    public String toString () {
        return "SmbTree[share=" + this.share + ",service=" + this.service + ",tid=" + this.tid + ",inDfs=" + this.inDfs + ",inDomainDfs="
                + this.inDomainDfs + ",connectionState=" + this.connectionState + ",usage=" + this.usageCount.get() + "]";
    }

}
