/**
 * © 2017 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 14.03.2017 by mbechler
 */
package jcifs.smb;


import java.io.IOException;
import java.net.UnknownHostException;
import java.util.Random;

import org.apache.log4j.Logger;

import jcifs.CIFSContext;
import jcifs.SmbConstants;
import jcifs.netbios.UniAddress;
import jcifs.smb.SmbTransport.ServerData;


/**
 * @author mbechler
 *
 */
public class SmbTreeConnection {

    private static final Logger log = Logger.getLogger(SmbTreeConnection.class);

    private final CIFSContext ctx;
    private SmbTree tree;
    private SmbTransport exclusiveTransport;
    private boolean nonPooled;

    private static final Random RAND = new Random();


    /**
     * @param ctx
     * 
     */
    public SmbTreeConnection ( CIFSContext ctx ) {
        this.ctx = ctx;
    }


    /**
     * @return session that this file has been loaded through
     */
    public SmbSession getSession () {
        SmbTree t = this.tree;
        if ( t != null ) {
            return t.session;
        }
        return null;
    }


    /**
     * @param cap
     * @return whether the capability is available
     * @throws SmbException
     */
    public boolean hasCapability ( int cap ) throws SmbException {
        SmbSession s = this.getSession();
        if ( s != null ) {
            return s.getTransport().hasCapability(cap);
        }
        throw new SmbException("Not connected");
    }


    synchronized void disconnect ( boolean inError ) {
        SmbTransport transport = this.getSession().transport();
        synchronized ( transport ) {
            SmbTree t = this.tree;
            if ( t != null ) {
                t.treeDisconnect(inError);
                t.session.logoff(inError);
                this.tree = null;
            }
        }
    }


    void send ( SmbFileLocator loc, ServerMessageBlock request, ServerMessageBlock response ) throws SmbException {
        send(loc, request, response, true);
    }


    void send ( SmbFileLocator loc, ServerMessageBlock request, ServerMessageBlock response, boolean timeout ) throws SmbException {
        String savedPath = ( request != null ) ? request.path : null;
        for ( int retries = 1; retries < this.ctx.getConfig().getMaxRequestRetries(); retries++ ) {
            try {
                send0(loc, request, response, timeout);
                return;
            }
            catch ( SmbException smbe ) {
                if ( smbe.getNtStatus() != NtStatus.NT_STATUS_INVALID_PARAMETER ) {
                    throw smbe;
                }
                log.debug("send", smbe);
            }
            // If we get here, we got the 'The Parameter is incorrect' error.
            // Disconnect and try again from scratch.
            if ( log.isDebugEnabled() )
                log.debug("Retrying (" + retries + ") send: " + request);
            disconnect(true);
            try {
                Thread.sleep(500 + RAND.nextInt(5000));
            }
            catch ( InterruptedException e ) {
                log.debug("send", e);
            }
            if ( request != null ) {
                // resolveDfs() and tree.send() modify the request packet.
                // I want to restore it before retrying. request.reset()
                // restores almost everything that was modified, except the path.
                request.reset();
                request.path = savedPath;
            }
            if ( response != null )
                response.reset();
            connectWrapException(loc);
        }
    }


    private void send0 ( SmbFileLocator loc, ServerMessageBlock request, ServerMessageBlock response, boolean timeout )
            throws SmbException, DfsReferral {
        for ( ;; ) {
            ensureDFSResolved(loc, request);
            try {
                this.tree.send(request, response, timeout);
                break;
            }
            catch ( DfsReferral dre ) {
                if ( dre.resolveHashes ) {
                    throw dre;
                }
                request.reset();
                log.trace("send0", dre);
            }
        }
    }


    /**
     * @param loc
     * @return tree handle
     * @throws SmbException
     */
    public SmbTreeHandleImpl connectWrapException ( SmbFileLocator loc ) throws SmbException {
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
    public synchronized SmbTreeHandleImpl connect ( SmbFileLocator loc ) throws IOException {
        if ( isConnected() && getSession().getTransport().tconHostName == null ) {
            /*
             * Tree/session thinks it is connected but transport disconnected
             * under it, reset tree to reflect the truth.
             */
            log.debug("Disconnecting failed tree and session");
            disconnect(true);
        }

        if ( isConnected() ) {
            log.trace("Already connected");
            return new SmbTreeHandleImpl(loc, this);
        }

        loc.canonicalizePath();
        UniAddress addr = loc.getFirstAddress();
        for ( ;; ) {
            try {
                return connectHost(loc, addr);
            }
            catch ( SmbAuthException sae ) {
                throw sae; // Prevents account lockout on servers with multiple IPs
            }
            catch ( SmbException se ) {
                if ( ( addr = loc.getNextAddress() ) == null )
                    throw se;
                log.debug("Connect failed", se);
            }
        }
    }


    /**
     * @return whether we have a valid tree connection
     */
    public synchronized boolean isConnected () {
        return this.tree != null && this.tree.isConnected();
    }


    /**
     * 
     * @param loc
     * @param addr
     * @return tree handle
     * @throws IOException
     */
    public synchronized SmbTreeHandleImpl connectHost ( SmbFileLocator loc, UniAddress addr ) throws IOException {
        SmbTransport trans;
        SmbTree t;
        if ( log.isDebugEnabled() ) {
            log.debug("Tree is " + this.tree);
        }
        if ( this.tree != null ) {
            trans = getSession().getTransport();
            t = this.tree;
        }
        else if ( this.nonPooled ) {
            if ( log.isDebugEnabled() ) {
                log.debug("Using exclusive transport for " + this);
            }
            this.exclusiveTransport = this.ctx.getTransportPool().getSmbTransport(this.ctx, addr, loc.getPort(), true, loc.shouldForceSigning());
            trans = this.exclusiveTransport;
            trans.setDontTimeout(true);
            t = trans.getSmbSession(this.ctx).getSmbTree(loc.getShare(), null);
        }
        else {
            trans = this.ctx.getTransportPool().getSmbTransport(this.ctx, addr, loc.getPort(), false, loc.shouldForceSigning());
            t = trans.getSmbSession(this.ctx).getSmbTree(loc.getShare(), null);
        }

        this.tree = connectTree(loc, addr, trans, t);
        return new SmbTreeHandleImpl(loc, this);
    }


    /**
     * @param loc
     * @param addr
     * @param trans
     * @param t
     * @throws SmbAuthException
     * @throws SmbException
     */
    private SmbTree connectTree ( SmbFileLocator loc, UniAddress addr, SmbTransport trans, SmbTree t ) throws SmbAuthException, SmbException {
        if ( log.isDebugEnabled() && ( trans.flags2 & SmbConstants.FLAGS2_SECURITY_SIGNATURES ) != 0 && !trans.server.signaturesRequired
                && !loc.isIPC() && !this.ctx.getConfig().isSigningEnforced() ) {
            log.debug("Signatures for file enabled but not required " + this);
        }

        String hostName = loc.getServerWithDfs();
        DfsReferral referral = this.ctx.getDfs().resolve(this.ctx, hostName, t.share, null);
        t.inDomainDfs = referral != null;
        if ( t.inDomainDfs ) {
            // make sure transport is connected
            trans.connect();
            t.connectionState = 2;
        }

        try {
            if ( log.isTraceEnabled() )
                log.trace("doConnect: " + addr);

            t.treeConnect(null, null);
        }
        catch ( SmbAuthException sae ) {
            log.debug("Authentication failed", sae);
            SmbSession ssn;
            if ( loc.isIPC() ) { // IPC$ - try "anonymous" credentials
                ssn = trans.getSmbSession(this.ctx.withAnonymousCredentials());
                t = ssn.getSmbTree(null, null);
                t.treeConnect(null, null);
            }
            else if ( this.ctx.renewCredentials(loc.getURL().toString(), sae) ) {
                log.debug("Trying to renew credentials after auth error");
                ssn = trans.getSmbSession(this.ctx);
                t = ssn.getSmbTree(loc.getShare(), null);
                t.inDomainDfs = referral != null;
                if ( this.tree.inDomainDfs ) {
                    this.tree.connectionState = 2;
                }
                t.treeConnect(null, null);
            }
            else {
                throw sae;
            }
        }
        return t;
    }


    /**
     * @throws SmbException
     */
    public void close () throws SmbException {
        if ( this.exclusiveTransport != null ) {
            try {
                log.debug("Disconnecting exclusive transport");
                this.exclusiveTransport.doDisconnect(false);
            }
            catch ( IOException e ) {
                throw new SmbException("Failed to close exclusive transport");
            }
        }
    }


    SmbFileLocator ensureDFSResolved ( SmbFileLocator loc ) throws SmbException {
        return ensureDFSResolved(loc, null);
    }


    SmbFileLocator ensureDFSResolved ( SmbFileLocator loc, ServerMessageBlock request ) throws SmbException {
        if ( request instanceof SmbComClose )
            return loc;

        for ( int retries = 0; retries < 1 + this.ctx.getConfig().getMaxRequestRetries(); retries++ ) {
            try {
                return resolveDfs0(loc, request);
            }
            catch ( NullPointerException npe ) {
                // Bug where transport or tconHostName is null indicates
                // failed to clean up properly from dropped connection.
                log.debug("resolveDfs", npe);
            }
            catch ( SmbException smbe ) {
                // The connection may have been dropped?
                if ( smbe.getNtStatus() != NtStatus.NT_STATUS_NOT_FOUND ) {
                    throw smbe;
                }
                log.debug("resolveDfs", smbe);
            }
            // If we get here, we apparently have a bad connection.
            // Disconnect and try again.
            if ( log.isDebugEnabled() )
                log.debug("Retrying (" + retries + ") resolveDfs: " + request);
            disconnect(true);
            try {
                Thread.sleep(500 + RAND.nextInt(5000));
            }
            catch ( InterruptedException e ) {
                log.debug("resolveDfs", e);
            }
        }

        return loc;
    }


    private SmbFileLocator resolveDfs0 ( SmbFileLocator loc, ServerMessageBlock request ) throws SmbException {
        try ( SmbTreeHandle connectWrapException = connectWrapException(loc) ) {
            SmbSession session = getSession();
            SmbTransport transport = session.getTransport();
            DfsReferral dr = this.ctx.getDfs().resolve(this.ctx, transport.tconHostName, this.tree.share, loc.getUncPath());

            if ( dr != null ) {
                if ( log.isDebugEnabled() ) {
                    log.debug("Info " + transport.tconHostName + "\\" + this.tree.share + loc.getUncPath() + " -> " + dr);
                }
                String service = this.tree != null ? this.tree.service : null;

                if ( request != null ) {
                    switch ( request.command ) {
                    case ServerMessageBlock.SMB_COM_TRANSACTION:
                    case ServerMessageBlock.SMB_COM_TRANSACTION2:
                        switch ( ( (SmbComTransaction) request ).subCommand & 0xFF ) {
                        case SmbComTransaction.TRANS2_GET_DFS_REFERRAL:
                            break;
                        default:
                            service = "A:";
                        }
                        break;
                    default:
                        service = "A:";
                    }
                }

                String dunc = loc.handleDFSReferral(followReferrals(loc, dr, service), request != null && request.path != null ? request.path : null);

                if ( request != null ) {
                    request.path = dunc;
                    request.flags2 |= SmbConstants.FLAGS2_RESOLVE_PATHS_IN_DFS;
                }

                return loc;
            }
            else if ( this.tree.inDomainDfs && ! ( request instanceof NtTransQuerySecurityDesc ) && ! ( request instanceof SmbComClose )
                    && ! ( request instanceof SmbComFindClose2 ) ) {
                throw new SmbException(NtStatus.NT_STATUS_NOT_FOUND, false);
            }
            else {
                log.trace("Not in DFS");
                if ( request != null )
                    request.flags2 &= ~SmbConstants.FLAGS2_RESOLVE_PATHS_IN_DFS;

                return loc;
            }
        }
    }


    /**
     * @param loc
     * @param dr
     * @param service
     * @return final referral
     * @throws SmbException
     */
    private DfsReferral followReferrals ( SmbFileLocator loc, DfsReferral dr, String service ) throws SmbException {
        SmbException se;
        DfsReferral start = dr;
        do {
            try {
                if ( log.isTraceEnabled() ) {
                    log.trace("DFS redirect: " + dr);
                }

                UniAddress addr = this.ctx.getNameServiceClient().getByName(dr.server);
                SmbTransport trans = this.ctx.getTransportPool().getSmbTransport(this.ctx, addr, loc.getPort(), false, loc.shouldForceSigning());

                synchronized ( trans ) {
                    /*
                     * This is a key point. This is where we set the "tree" of this file which
                     * is like changing the rug out from underneath our feet.
                     */
                    /*
                     * Technically we should also try to authenticate here but that means doing the session
                     * setup
                     * and
                     * tree connect separately. For now a simple connect will at least tell us if the host is
                     * alive.
                     * That should be sufficient for 99% of the cases. We can revisit this again for 2.0.
                     */
                    trans.connect();
                    this.tree = trans.getSmbSession(this.ctx).getSmbTree(dr.share, service);
                    if ( dr != start && dr.key != null ) {
                        dr.map.put(dr.key, dr);
                    }
                }

                se = null;
                break;
            }
            catch ( IOException ioe ) {
                log.debug("Error checking dfs root", ioe);
                if ( ioe instanceof SmbException ) {
                    se = (SmbException) ioe;
                }
                else {
                    se = new SmbException("Failed to connect to server " + dr.server, ioe);
                }
            }

            dr = dr.next;
        }
        while ( dr != start );

        if ( se != null )
            throw se;
        return dr;
    }


    /**
     * @param np
     */
    public void setNonPool ( boolean np ) {
        this.nonPooled = true;
    }


    /**
     * @return the currently connected tid
     */
    public int getTreeId () {
        SmbTree t = this.tree;
        if ( t == null ) {
            return -1;
        }
        return t.tree_num;
    }


    /**
     * 
     * @return server data provided during negotiation
     */
    public ServerData getServerData () {
        return getSession().getTransport().server;
    }


    /**
     * @return the service we are connected to
     */
    public String getConnectedService () {
        return this.tree.service;
    }


    /**
     * @return the share we are connected to
     */
    public String getConnectedShare () {
        return this.tree.share;
    }


    /**
     * @param other
     * @return whether the connection refers to the same tree
     */
    public boolean isSame ( SmbTreeConnection other ) {
        return this.tree.equals(other.tree);
    }

}
