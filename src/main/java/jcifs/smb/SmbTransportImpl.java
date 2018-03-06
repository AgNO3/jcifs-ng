/* jcifs smb client library in Java
 * Copyright (C) 2005  "Michael B. Allen" <jcifs at samba dot org>
 *                  "Eric Glass" <jcifs at samba dot org>
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


import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import javax.crypto.Cipher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.Address;
import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.DfsReferralData;
import jcifs.DialectVersion;
import jcifs.SmbConstants;
import jcifs.SmbTransport;
import jcifs.internal.CommonServerMessageBlock;
import jcifs.internal.CommonServerMessageBlockRequest;
import jcifs.internal.CommonServerMessageBlockResponse;
import jcifs.internal.RequestWithPath;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.SMBSigningDigest;
import jcifs.internal.SmbNegotiation;
import jcifs.internal.SmbNegotiationResponse;
import jcifs.internal.dfs.DfsReferralDataImpl;
import jcifs.internal.dfs.DfsReferralRequestBuffer;
import jcifs.internal.dfs.DfsReferralResponseBuffer;
import jcifs.internal.dfs.Referral;
import jcifs.internal.smb1.AndXServerMessageBlock;
import jcifs.internal.smb1.ServerMessageBlock;
import jcifs.internal.smb1.com.SmbComBlankResponse;
import jcifs.internal.smb1.com.SmbComLockingAndX;
import jcifs.internal.smb1.com.SmbComNegotiate;
import jcifs.internal.smb1.com.SmbComNegotiateResponse;
import jcifs.internal.smb1.com.SmbComReadAndXResponse;
import jcifs.internal.smb1.trans.SmbComTransaction;
import jcifs.internal.smb1.trans.SmbComTransactionResponse;
import jcifs.internal.smb1.trans2.Trans2GetDfsReferral;
import jcifs.internal.smb1.trans2.Trans2GetDfsReferralResponse;
import jcifs.internal.smb2.ServerMessageBlock2;
import jcifs.internal.smb2.ServerMessageBlock2Request;
import jcifs.internal.smb2.ServerMessageBlock2Response;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.smb2.ioctl.Smb2IoctlRequest;
import jcifs.internal.smb2.lock.Smb2OplockBreakNotification;
import jcifs.internal.smb2.nego.EncryptionNegotiateContext;
import jcifs.internal.smb2.nego.Smb2NegotiateRequest;
import jcifs.internal.smb2.nego.Smb2NegotiateResponse;
import jcifs.netbios.Name;
import jcifs.netbios.NbtException;
import jcifs.netbios.SessionRequestPacket;
import jcifs.netbios.SessionServicePacket;
import jcifs.util.Crypto;
import jcifs.util.Encdec;
import jcifs.util.Hexdump;
import jcifs.util.transport.Request;
import jcifs.util.transport.Response;
import jcifs.util.transport.Transport;
import jcifs.util.transport.TransportException;


/**
 * 
 */
class SmbTransportImpl extends Transport implements SmbTransportInternal, SmbConstants {

    private static Logger log = LoggerFactory.getLogger(SmbTransportImpl.class);

    private boolean smb2 = false;
    private InetAddress localAddr;
    private int localPort;
    private Address address;
    private Socket socket;
    private int port;
    private final AtomicLong mid = new AtomicLong();
    private OutputStream out;
    private InputStream in;
    private final byte[] sbuf = new byte[1024]; /* small local buffer */
    private long sessionExpiration;
    private final List<SmbSessionImpl> sessions = new LinkedList<>();

    private String tconHostName = null;

    private final CIFSContext transportContext;
    private final boolean signingEnforced;

    private SmbNegotiationResponse negotiated;

    private SMBSigningDigest digest;

    private final Semaphore credits = new Semaphore(1, true);

    private final int desiredCredits = 512;

    private byte[] preauthIntegrityHash = new byte[64];


    SmbTransportImpl ( CIFSContext tc, Address address, int port, InetAddress localAddr, int localPort, boolean forceSigning ) {
        this.transportContext = tc;

        this.signingEnforced = forceSigning || this.getContext().getConfig().isSigningEnforced();
        this.sessionExpiration = System.currentTimeMillis() + tc.getConfig().getSessionTimeout();

        this.address = address;
        this.port = port;
        this.localAddr = localAddr;
        this.localPort = localPort;

    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Transport#getResponseTimeout()
     */
    @Override
    protected int getResponseTimeout ( Request req ) {
        if ( req instanceof CommonServerMessageBlockRequest ) {
            Integer overrideTimeout = ( (CommonServerMessageBlockRequest) req ).getOverrideTimeout();
            if ( overrideTimeout != null ) {
                return overrideTimeout;
            }
        }
        return getContext().getConfig().getResponseTimeout();
    }


    @Override
    public Address getRemoteAddress () {
        return this.address;
    }


    @Override
    public String getRemoteHostName () {
        return this.tconHostName;
    }


    /**
     * 
     * @return number of sessions on this transport
     */
    public int getNumSessions () {
        return this.sessions.size();
    }


    @Override
    public int getInflightRequests () {
        return this.response_map.size();
    }


    @Override
    public boolean isDisconnected () {
        return super.isDisconnected() || this.socket.isClosed();
    }


    @Override
    public boolean isFailed () {
        return super.isFailed() || this.socket.isClosed();
    }


    @Override
    public boolean hasCapability ( int cap ) throws SmbException {
        return getNegotiateResponse().haveCapabilitiy(cap);
    }


    /**
     * @return the negotiated
     * @throws SmbException
     */
    SmbNegotiationResponse getNegotiateResponse () throws SmbException {
        try {
            if ( this.negotiated == null ) {
                connect(this.transportContext.getConfig().getResponseTimeout());
            }
        }
        catch ( IOException ioe ) {
            throw new SmbException(ioe.getMessage(), ioe);
        }
        return this.negotiated;
    }


    /**
     * @return whether this is SMB2 transport
     * @throws SmbException
     */
    @Override
    public boolean isSMB2 () throws SmbException {
        return this.smb2 || getNegotiateResponse() instanceof Smb2NegotiateResponse;
    }


    /**
     * @param digest
     */
    public void setDigest ( SMBSigningDigest digest ) {
        this.digest = digest;
    }


    /**
     * @return the digest
     */
    public SMBSigningDigest getDigest () {
        return this.digest;
    }


    /**
     * @return the context associated with this transport connection
     */
    @Override
    public CIFSContext getContext () {
        return this.transportContext;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Transport#acquire()
     */
    @Override
    public SmbTransportImpl acquire () {
        return (SmbTransportImpl) super.acquire();
    }


    /**
     * @return the server's encryption key
     */
    @Override
    public byte[] getServerEncryptionKey () {
        if ( this.negotiated == null ) {
            return null;
        }

        if ( this.negotiated instanceof SmbComNegotiateResponse ) {
            return ( (SmbComNegotiateResponse) this.negotiated ).getServerData().encryptionKey;
        }
        return null;
    }


    @Override
    public boolean isSigningOptional () throws SmbException {
        if ( this.signingEnforced ) {
            return false;
        }
        SmbNegotiationResponse nego = getNegotiateResponse();
        return nego.isSigningNegotiated() && !nego.isSigningRequired();
    }


    @Override
    public boolean isSigningEnforced () throws SmbException {
        if ( this.signingEnforced ) {
            return true;
        }
        return getNegotiateResponse().isSigningRequired();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.SmbTransport#unwrap(java.lang.Class)
     */
    @SuppressWarnings ( "unchecked" )
    @Override
    public <T extends SmbTransport> T unwrap ( Class<T> type ) {
        if ( type.isAssignableFrom(this.getClass()) ) {
            return (T) this;
        }
        throw new ClassCastException();
    }


    /**
     * 
     * @param tf
     * @return a session for the context
     */
    @Override
    public SmbSessionImpl getSmbSession ( CIFSContext tf ) {
        return getSmbSession(tf, null, null);
    }


    /**
     * 
     * @param tf
     *            context to use
     * @return a session for the context
     */
    @Override
    @SuppressWarnings ( "resource" )
    public synchronized SmbSessionImpl getSmbSession ( CIFSContext tf, String targetHost, String targetDomain ) {
        long now;

        if ( log.isTraceEnabled() ) {
            log.trace("Currently " + this.sessions.size() + " session(s) active for " + this);
        }

        if ( targetHost != null ) {
            targetHost = targetHost.toLowerCase(Locale.ROOT);
        }

        if ( targetDomain != null ) {
            targetDomain = targetDomain.toUpperCase(Locale.ROOT);
        }

        ListIterator<SmbSessionImpl> iter = this.sessions.listIterator();
        while ( iter.hasNext() ) {
            SmbSessionImpl ssn = iter.next();
            if ( ssn.matches(tf, targetHost, targetDomain) ) {
                if ( log.isTraceEnabled() ) {
                    log.trace("Reusing existing session " + ssn);
                }
                return ssn.acquire();
            }
            else if ( log.isTraceEnabled() ) {
                log.trace("Existing session " + ssn + " does not match " + tf.getCredentials());
            }
        }

        /* logoff old sessions */
        if ( tf.getConfig().getSessionTimeout() > 0 && this.sessionExpiration < ( now = System.currentTimeMillis() ) ) {
            this.sessionExpiration = now + tf.getConfig().getSessionTimeout();
            iter = this.sessions.listIterator();
            while ( iter.hasNext() ) {
                SmbSessionImpl ssn = iter.next();
                if ( ssn.getExpiration() != null && ssn.getExpiration() < now && !ssn.isInUse() ) {
                    if ( log.isDebugEnabled() ) {
                        log.debug("Closing session after timeout " + ssn);
                    }
                    ssn.logoff(false, false);
                }
            }
        }
        SmbSessionImpl ssn = new SmbSessionImpl(tf, targetHost, targetDomain, this);
        if ( log.isDebugEnabled() ) {
            log.debug("Establishing new session " + ssn + " on " + this.name);
        }
        this.sessions.add(ssn);
        return ssn;
    }


    boolean matches ( Address addr, int prt, InetAddress laddr, int lprt, String hostName ) {
        if ( this.state == 5 || this.state == 6 ) {
            // don't reuse disconnecting/disconnected transports
            return false;
        }
        if ( hostName == null )
            hostName = addr.getHostName();
        return ( this.tconHostName == null || hostName.equalsIgnoreCase(this.tconHostName) ) && addr.equals(this.address)
                && ( prt == 0 || prt == this.port ||
                /* port 139 is ok if 445 was requested */
                        ( prt == 445 && this.port == 139 ) )
                && ( laddr == this.localAddr || ( laddr != null && laddr.equals(this.localAddr) ) ) && lprt == this.localPort;
    }


    void ssn139 () throws IOException {
        CIFSContext tc = this.transportContext;
        Name calledName = new Name(tc.getConfig(), this.address.firstCalledName(), 0x20, null);
        do {
            this.socket = new Socket();
            if ( this.localAddr != null )
                this.socket.bind(new InetSocketAddress(this.localAddr, this.localPort));
            this.socket.connect(new InetSocketAddress(this.address.getHostAddress(), 139), tc.getConfig().getConnTimeout());
            this.socket.setSoTimeout(tc.getConfig().getSoTimeout());

            this.out = this.socket.getOutputStream();
            this.in = this.socket.getInputStream();

            SessionServicePacket ssp = new SessionRequestPacket(tc.getConfig(), calledName, tc.getNameServiceClient().getLocalName());
            this.out.write(this.sbuf, 0, ssp.writeWireFormat(this.sbuf, 0));
            if ( readn(this.in, this.sbuf, 0, 4) < 4 ) {
                try {
                    this.socket.close();
                }
                catch ( IOException ioe ) {
                    log.debug("Failed to close socket", ioe);
                }
                throw new SmbException("EOF during NetBIOS session request");
            }
            switch ( this.sbuf[ 0 ] & 0xFF ) {
            case SessionServicePacket.POSITIVE_SESSION_RESPONSE:
                if ( log.isDebugEnabled() ) {
                    log.debug("session established ok with " + this.address);
                }
                return;
            case SessionServicePacket.NEGATIVE_SESSION_RESPONSE:
                int errorCode = this.in.read() & 0xFF;
                switch ( errorCode ) {
                case NbtException.CALLED_NOT_PRESENT:
                case NbtException.NOT_LISTENING_CALLED:
                    this.socket.close();
                    break;
                default:
                    disconnect(true);
                    throw new NbtException(NbtException.ERR_SSN_SRVC, errorCode);
                }
                break;
            case -1:
                disconnect(true);
                throw new NbtException(NbtException.ERR_SSN_SRVC, NbtException.CONNECTION_REFUSED);
            default:
                disconnect(true);
                throw new NbtException(NbtException.ERR_SSN_SRVC, 0);
            }
        }
        while ( ( calledName.name = this.address.nextCalledName(tc) ) != null );

        throw new IOException("Failed to establish session with " + this.address);
    }


    private SmbNegotiation negotiate ( int prt ) throws IOException {
        /*
         * We cannot use Transport.sendrecv() yet because
         * the Transport thread is not setup until doConnect()
         * returns and we want to suppress all communication
         * until we have properly negotiated.
         */
        synchronized ( this.inLock ) {
            if ( prt == 139 ) {
                ssn139();
            }
            else {
                if ( prt == 0 )
                    prt = DEFAULT_PORT; // 445

                this.socket = new Socket();
                if ( this.localAddr != null )
                    this.socket.bind(new InetSocketAddress(this.localAddr, this.localPort));
                this.socket.connect(new InetSocketAddress(this.address.getHostAddress(), prt), this.transportContext.getConfig().getConnTimeout());
                this.socket.setSoTimeout(this.transportContext.getConfig().getSoTimeout());

                this.out = this.socket.getOutputStream();
                this.in = this.socket.getInputStream();
            }

            if ( this.smb2 || this.getContext().getConfig().isUseSMB2OnlyNegotiation() ) {
                log.debug("Using SMB2 only negotiation");
                return negotiate2(null);
            }

            SmbComNegotiate comNeg = new SmbComNegotiate(getContext().getConfig(), this.signingEnforced);
            int n = negotiateWrite(comNeg, true);
            negotiatePeek();

            SmbNegotiationResponse resp = null;

            if ( !this.smb2 ) {
                if ( this.getContext().getConfig().getMinimumVersion().isSMB2() ) {
                    throw new CIFSException("Server does not support SMB2");
                }
                resp = new SmbComNegotiateResponse(getContext());
                resp.decode(this.sbuf, 4);
                resp.received();

                if ( log.isTraceEnabled() ) {
                    log.trace(resp.toString());
                    log.trace(Hexdump.toHexString(this.sbuf, 4, n));
                }
            }
            else {
                Smb2NegotiateResponse r = new Smb2NegotiateResponse(getContext().getConfig());
                r.decode(this.sbuf, 4);
                r.received();
                if ( r.getDialectRevision() != Smb2Constants.SMB2_DIALECT_ANY && r.getDialectRevision() != Smb2Constants.SMB2_DIALECT_0202 ) {
                    throw new CIFSException("Server returned invalid dialect verison in multi protocol negotiation");
                }
                return negotiate2(r);
            }

            int permits = resp.getInitialCredits() - 1;
            if ( permits > 0 ) {
                this.credits.release(permits);
            }
            Arrays.fill(this.sbuf, (byte) 0);
            return new SmbNegotiation(comNeg, resp, null, null);
        }
    }


    /**
     * @return
     * @throws IOException
     */
    private int negotiateWrite ( CommonServerMessageBlockRequest req, boolean setmid ) throws IOException {
        if ( setmid ) {
            makeKey(req);
        }
        else {
            req.setMid(0);
            this.mid.set(1);
        }
        int n = req.encode(this.sbuf, 4);
        Encdec.enc_uint32be(n & 0xFFFF, this.sbuf, 0); /* 4 byte ssn msg header */

        if ( log.isTraceEnabled() ) {
            log.trace(req.toString());
            log.trace(Hexdump.toHexString(this.sbuf, 4, n));
        }

        this.out.write(this.sbuf, 0, 4 + n);
        this.out.flush();
        log.trace("Wrote negotiate request");
        return n;
    }


    /**
     * @throws SocketException
     * @throws IOException
     */
    private void negotiatePeek () throws SocketException, IOException {
        /*
         * Note the Transport thread isn't running yet so we can
         * read from the socket here.
         */
        try {
            this.socket.setSoTimeout(this.transportContext.getConfig().getConnTimeout());
            if ( peekKey() == null ) /* try to read header */
                throw new IOException("transport closed in negotiate");
        }
        finally {
            this.socket.setSoTimeout(this.transportContext.getConfig().getSoTimeout());
        }
        int size = Encdec.dec_uint16be(this.sbuf, 2) & 0xFFFF;
        if ( size < 33 || ( 4 + size ) > this.sbuf.length ) {
            throw new IOException("Invalid payload size: " + size);
        }
        int hdrSize = this.smb2 ? Smb2Constants.SMB2_HEADER_LENGTH : SMB1_HEADER_LENGTH;
        readn(this.in, this.sbuf, 4 + hdrSize, size - hdrSize);
        log.trace("Read negotiate response");
    }


    /**
     * @param first
     * @param n
     * @return
     * @throws IOException
     * @throws SocketException
     * @throws InterruptedException
     */
    private SmbNegotiation negotiate2 ( Smb2NegotiateResponse first ) throws IOException, SocketException {
        int size = 0;

        int securityMode = getRequestSecurityMode(first);

        // further negotiation needed
        Smb2NegotiateRequest smb2neg = new Smb2NegotiateRequest(getContext().getConfig(), securityMode);

        if ( this.credits.drainPermits() == 0 ) {
            throw new IOException("No credits for negotiate");
        }
        Smb2NegotiateResponse r = null;
        byte[] negoReqBuffer = null;
        byte[] negoRespBuffer = null;
        try {
            smb2neg.setRequestCredits(Math.max(1, this.desiredCredits - this.credits.availablePermits()));

            int reqLen = negotiateWrite(smb2neg, first != null);
            boolean doPreauth = getContext().getConfig().getMaximumVersion().atLeast(DialectVersion.SMB311);
            if ( doPreauth ) {
                negoReqBuffer = new byte[reqLen];
                System.arraycopy(this.sbuf, 4, negoReqBuffer, 0, reqLen);
            }

            negotiatePeek();

            r = smb2neg.initResponse(getContext());
            int respLen = r.decode(this.sbuf, 4);
            r.received();

            if ( doPreauth ) {
                negoRespBuffer = new byte[respLen];
                System.arraycopy(this.sbuf, 4, negoRespBuffer, 0, respLen);
            }
            else {
                negoReqBuffer = null;
            }

            if ( log.isTraceEnabled() ) {
                log.trace(r.toString());
                log.trace(Hexdump.toHexString(this.sbuf, 4, size));
            }
            return new SmbNegotiation(smb2neg, r, negoReqBuffer, negoRespBuffer);
        }
        finally {
            int grantedCredits = r != null ? r.getGrantedCredits() : 0;
            if ( grantedCredits == 0 ) {
                grantedCredits = 1;
            }
            this.credits.release(grantedCredits);
            Arrays.fill(this.sbuf, (byte) 0);
        }
    }


    /**
     * Connect the transport
     * 
     * @throws SmbException
     */
    @Override
    public boolean ensureConnected () throws SmbException {
        try {
            return super.connect(this.transportContext.getConfig().getResponseTimeout());
        }
        catch ( TransportException te ) {
            throw new SmbException("Failed to connect: " + this.address, te);
        }

    }


    @Override
    protected void doConnect () throws IOException {
        /*
         * Negotiate Protocol Request / Response
         */
        if ( log.isDebugEnabled() ) {
            log.debug("Connecting in state " + this.state + " addr " + this.address.getHostAddress());
        }

        SmbNegotiation resp;
        try {
            resp = negotiate(this.port);
        }
        catch ( IOException ce ) {
            if ( getContext().getConfig().isPort139FailoverEnabled() ) {
                this.port = ( this.port == 0 || this.port == DEFAULT_PORT ) ? 139 : DEFAULT_PORT;
                this.smb2 = false;
                this.mid.set(0);
                resp = negotiate(this.port);
            }
            else {
                throw ce;
            }
        }

        if ( resp == null || resp.getResponse() == null ) {
            throw new SmbException("Failed to connect.");
        }

        if ( log.isDebugEnabled() ) {
            log.debug("Negotiation response on " + this.name + " :" + resp);
        }

        if ( !resp.getResponse().isValid(getContext(), resp.getRequest()) ) {
            throw new SmbException("This client is not compatible with the server.");
        }

        boolean serverRequireSig = resp.getResponse().isSigningRequired();
        boolean serverEnableSig = resp.getResponse().isSigningEnabled();
        if ( log.isDebugEnabled() ) {
            log.debug(
                "Signature negotiation enforced " + this.signingEnforced + " (server " + serverRequireSig + ") enabled "
                        + this.getContext().getConfig().isSigningEnabled() + " (server " + serverEnableSig + ")");
        }

        /* Adjust negotiated values */
        this.tconHostName = this.address.getHostName();
        this.negotiated = resp.getResponse();
        if ( resp.getResponse().getSelectedDialect().atLeast(DialectVersion.SMB311) ) {
            updatePreauthHash(resp.getRequestRaw());
            updatePreauthHash(resp.getResponseRaw());
            if ( log.isDebugEnabled() ) {
                log.debug("Preauth hash after negotiate " + Hexdump.toHexString(this.preauthIntegrityHash));
            }
        }
    }


    protected synchronized void doDisconnect ( boolean hard ) throws IOException {
        doDisconnect(hard, false);
    }


    @Override
    protected synchronized boolean doDisconnect ( boolean hard, boolean inUse ) throws IOException {
        ListIterator<SmbSessionImpl> iter = this.sessions.listIterator();
        boolean wasInUse = false;
        long l = getUsageCount();
        if ( ( inUse && l != 1 ) || ( !inUse && l > 0 ) ) {
            log.warn("Disconnecting transport while still in use " + this + ": " + this.sessions);
            wasInUse = true;
        }

        if ( log.isDebugEnabled() ) {
            log.debug("Disconnecting transport " + this);
        }

        try {
            if ( log.isTraceEnabled() ) {
                log.trace("Currently " + this.sessions.size() + " session(s) active for " + this);
            }
            while ( iter.hasNext() ) {
                @SuppressWarnings ( "resource" )
                SmbSessionImpl ssn = iter.next();
                try {
                    wasInUse |= ssn.logoff(hard, false);
                }
                catch ( Exception e ) {
                    log.debug("Failed to close session", e);
                }
                finally {
                    iter.remove();
                }
            }

            if ( this.socket != null ) {
                this.socket.shutdownOutput();
                this.out.close();
                this.in.close();
                this.socket.close();
                log.trace("Socket closed");
            }
            else {
                log.trace("Not yet initialized");
            }
        }
        catch ( Exception e ) {
            log.debug("Exception in disconnect", e);
        }
        finally {
            this.socket = null;
            this.digest = null;
            this.tconHostName = null;
            this.transportContext.getTransportPool().removeTransport(this);
        }
        return wasInUse;
    }


    @Override
    protected long makeKey ( Request request ) throws IOException {
        long m = this.mid.incrementAndGet() - 1;
        if ( !this.smb2 ) {
            m = ( m % 32000 );
        }
        ( (CommonServerMessageBlock) request ).setMid(m);
        return m;
    }


    @Override
    protected Long peekKey () throws IOException {
        do {
            if ( ( readn(this.in, this.sbuf, 0, 4) ) < 4 ) {
                return null;
            }
        }
        while ( this.sbuf[ 0 ] == (byte) 0x85 ); /* Dodge NetBIOS keep-alive */
        /* read smb header */
        if ( ( readn(this.in, this.sbuf, 4, SmbConstants.SMB1_HEADER_LENGTH) ) < SmbConstants.SMB1_HEADER_LENGTH ) {
            return null;
        }

        if ( log.isTraceEnabled() ) {
            log.trace("New data read: " + this);
            log.trace(Hexdump.toHexString(this.sbuf, 4, 32));
        }

        for ( ;; ) {
            /*
             * 01234567
             * 00SSFSMB
             * 0 - 0's
             * S - size of payload
             * FSMB - 0xFF SMB magic #
             */

            if ( this.sbuf[ 0 ] == (byte) 0x00 && this.sbuf[ 4 ] == (byte) 0xFE && this.sbuf[ 5 ] == (byte) 'S' && this.sbuf[ 6 ] == (byte) 'M'
                    && this.sbuf[ 7 ] == (byte) 'B' ) {
                this.smb2 = true;
                // also read the rest of the header
                int lenDiff = Smb2Constants.SMB2_HEADER_LENGTH - SmbConstants.SMB1_HEADER_LENGTH;
                if ( readn(this.in, this.sbuf, 4 + SmbConstants.SMB1_HEADER_LENGTH, lenDiff) < lenDiff ) {
                    return null;
                }
                return (long) Encdec.dec_uint64le(this.sbuf, 28);
            }

            if ( this.sbuf[ 0 ] == (byte) 0x00 && this.sbuf[ 1 ] == (byte) 0x00 && ( this.sbuf[ 4 ] == (byte) 0xFF ) && this.sbuf[ 5 ] == (byte) 'S'
                    && this.sbuf[ 6 ] == (byte) 'M' && this.sbuf[ 7 ] == (byte) 'B' ) {
                break; /* all good (SMB) */
            }

            /* out of phase maybe? */
            /* inch forward 1 byte and try again */
            for ( int i = 0; i < 35; i++ ) {
                log.warn("Possibly out of phase, trying to resync " + Hexdump.toHexString(this.sbuf, 0, 16));
                this.sbuf[ i ] = this.sbuf[ i + 1 ];
            }
            int b;
            if ( ( b = this.in.read() ) == -1 )
                return null;
            this.sbuf[ 35 ] = (byte) b;
        }

        /*
         * Unless key returned is null or invalid Transport.loop() always
         * calls doRecv() after and no one else but the transport thread
         * should call doRecv(). Therefore it is ok to expect that the data
         * in sbuf will be preserved for copying into BUF in doRecv().
         */

        return (long) Encdec.dec_uint16le(this.sbuf, 34) & 0xFFFF;
    }


    @Override
    protected void doSend ( Request request ) throws IOException {

        CommonServerMessageBlock smb = (CommonServerMessageBlock) request;
        byte[] buffer = this.getContext().getBufferCache().getBuffer();
        try {
            // synchronize around encode and write so that the ordering for SMB1 signing can be maintained
            synchronized ( this.outLock ) {
                int n = smb.encode(buffer, 4);
                Encdec.enc_uint32be(n & 0xFFFF, buffer, 0); /* 4 byte session message header */
                if ( log.isTraceEnabled() ) {
                    do {
                        log.trace(smb.toString());
                    }
                    while ( smb instanceof AndXServerMessageBlock && ( smb = ( (AndXServerMessageBlock) smb ).getAndx() ) != null );
                    log.trace(Hexdump.toHexString(buffer, 4, n));

                }
                /*
                 * For some reason this can sometimes get broken up into another
                 * "NBSS Continuation Message" frame according to WireShark
                 */

                this.out.write(buffer, 0, 4 + n);
                this.out.flush();
            }
        }
        finally {
            this.getContext().getBufferCache().releaseBuffer(buffer);
        }
    }


    @SuppressWarnings ( "unchecked" )
    public <T extends CommonServerMessageBlockResponse> T sendrecv ( CommonServerMessageBlockRequest request, T response, Set<RequestParam> params )
            throws IOException {
        if ( request instanceof jcifs.internal.Request ) {
            if ( response == null ) {
                response = (T) ( (jcifs.internal.Request<?>) request ).initResponse(getContext());
            }
            else if ( isSMB2() ) {
                throw new IOException("Should not provide response argument for SMB2");
            }
        }
        else {
            request.setResponse(response);
        }
        if ( response == null ) {
            throw new IOException("Invalid response");
        }

        CommonServerMessageBlockRequest curHead = request;

        int maxSize = getContext().getConfig().getMaximumBufferSize();

        while ( curHead != null ) {
            CommonServerMessageBlockRequest nextHead = null;
            int totalSize = 0;
            int n = 0;
            CommonServerMessageBlockRequest last = null;
            CommonServerMessageBlockRequest chain = curHead;
            while ( chain != null ) {
                n++;
                int size = chain.size();
                int cost = chain.getCreditCost();
                CommonServerMessageBlockRequest next = chain.getNext();
                if ( log.isTraceEnabled() ) {
                    log.trace(
                        String.format("%s costs %d avail %d (%s)", chain.getClass().getName(), cost, this.credits.availablePermits(), this.name));
                }
                if ( ( next == null || chain.allowChain(next) ) && totalSize + size < maxSize && this.credits.tryAcquire(cost) ) {
                    totalSize += size;
                    last = chain;
                    chain = next;
                }
                else if ( last == null && totalSize + size > maxSize ) {
                    throw new SmbException(String.format("Request size %d exceeds allowable size %d: %s", size, maxSize, chain));
                }
                else if ( last == null ) {
                    // don't have enough credits/space for the first request, block until available
                    // for space there is nothing we can do, callers need to make sure that a single message fits

                    try {
                        long timeout = getResponseTimeout(chain);
                        if ( !params.contains(RequestParam.NO_TIMEOUT) ) {
                            this.credits.acquire(cost);
                        }
                        else {
                            if ( !this.credits.tryAcquire(cost, timeout, TimeUnit.MILLISECONDS) ) {
                                throw new SmbException("Failed to acquire credits in time");
                            }
                        }
                        totalSize += size;
                        // split off first request

                        synchronized ( chain ) {
                            CommonServerMessageBlockRequest snext = chain.split();
                            nextHead = snext;
                            if ( log.isDebugEnabled() && snext != null ) {
                                log.debug("Insufficient credits, send only first " + chain + " next is " + snext);
                            }
                        }
                        break;
                    }
                    catch ( InterruptedException e ) {
                        throw new InterruptedIOException("Failed to acquire credits, exzessive parallelism?");
                    }
                }
                else {
                    // not enough credits available or too big, split
                    if ( log.isDebugEnabled() ) {
                        log.debug("Not enough credits, split at " + last);
                    }
                    synchronized ( last ) {
                        nextHead = last.split();
                    }
                    break;
                }
            }

            int reqCredits = Math.max(1, this.desiredCredits - this.credits.availablePermits() - n + 1);
            if ( log.isTraceEnabled() ) {
                log.trace("Request credits " + reqCredits);
            }
            request.setRequestCredits(reqCredits);

            CommonServerMessageBlockRequest thisReq = curHead;
            try {
                CommonServerMessageBlockResponse resp = thisReq.getResponse();
                if ( log.isTraceEnabled() ) {
                    log.trace("Sending " + thisReq);
                }
                resp = super.sendrecv(curHead, resp, params);

                if ( !checkStatus(curHead, resp) ) {
                    if ( log.isDebugEnabled() ) {
                        log.debug("Breaking on error " + resp);
                    }
                    break;
                }

                if ( nextHead != null ) {
                    // prepare remaining
                    // (e.g. set session/tree/fileid returned by the previous requests)
                    resp.prepare(nextHead);
                }
                curHead = nextHead;
            }
            finally {
                CommonServerMessageBlockRequest curReq = thisReq;
                int grantedCredits = 0;
                // if
                while ( curReq != null ) {
                    if ( curReq.isResponseAsync() ) {
                        log.trace("Async");
                        break;
                    }

                    CommonServerMessageBlockResponse resp = curReq.getResponse();

                    if ( resp.isReceived() ) {
                        grantedCredits += resp.getGrantedCredits();
                    }
                    CommonServerMessageBlockRequest next = curReq.getNext();
                    if ( next == null ) {
                        break;
                    }
                    curReq = next;
                }
                if ( !isDisconnected() && !curReq.isResponseAsync() && !curReq.getResponse().isAsync() && !curReq.getResponse().isError()
                        && grantedCredits == 0 ) {
                    if ( this.credits.availablePermits() > 0 || n > 0 ) {
                        log.debug("Server " + this + " returned zero credits for " + curReq);
                    }
                    else {
                        log.warn("Server " + this + " took away all our credits");
                    }
                }
                else if ( !curReq.isResponseAsync() ) {
                    if ( log.isTraceEnabled() ) {
                        log.trace("Adding credits " + grantedCredits);
                    }
                    this.credits.release(grantedCredits);
                }
            }
        }

        if ( !response.isReceived() ) {
            throw new IOException("No response", response.getException());
        }
        return response;

    }


    @Override
    protected <T extends Response> boolean handleIntermediate ( Request request, T response ) {
        if ( !this.smb2 ) {
            return false;
        }
        ServerMessageBlock2Request<?> req = (ServerMessageBlock2Request<?>) request;
        ServerMessageBlock2Response resp = (ServerMessageBlock2Response) response;
        synchronized ( resp ) {
            if ( resp.isAsync() && !resp.isAsyncHandled() && resp.getStatus() == NtStatus.NT_STATUS_PENDING && resp.getAsyncId() != 0 ) {
                resp.setAsyncHandled(true);
                boolean first = !req.isAsync();
                req.setAsyncId(resp.getAsyncId());
                Long exp = resp.getExpiration();
                if ( exp != null ) {
                    resp.setExpiration(System.currentTimeMillis() + getResponseTimeout(request));
                }
                if ( log.isDebugEnabled() ) {
                    log.debug("Have intermediate reply " + response);
                }

                if ( first ) {
                    int credit = resp.getCredit();
                    if ( log.isDebugEnabled() ) {
                        log.debug("Credit from intermediate " + credit);
                    }
                    this.credits.release(credit);
                }
                return true;
            }
        }
        return false;
    }


    protected void doSend0 ( Request request ) throws IOException {
        try {
            doSend(request);
        }
        catch ( IOException ioe ) {
            log.warn("send failed", ioe);
            try {
                disconnect(true);
            }
            catch ( IOException ioe2 ) {
                ioe.addSuppressed(ioe2);
                log.error("disconnect failed", ioe2);
            }
            throw ioe;
        }
    }


    // must be synchronized with peekKey
    @Override
    protected void doRecv ( Response response ) throws IOException {
        CommonServerMessageBlock resp = (CommonServerMessageBlock) response;
        this.negotiated.setupResponse(response);
        try {
            if ( this.smb2 ) {
                doRecvSMB2(resp);
            }
            else {
                doRecvSMB1(resp);
            }
        }
        catch ( Exception e ) {
            log.warn("Failure decoding message, disconnecting transport", e);
            response.exception(e);
            synchronized ( response ) {
                response.notifyAll();
            }
            throw e;
        }

    }


    /**
     * @param response
     * @throws IOException
     * @throws SMBProtocolDecodingException
     */
    private void doRecvSMB2 ( CommonServerMessageBlock response ) throws IOException, SMBProtocolDecodingException {
        int size = ( Encdec.dec_uint16be(this.sbuf, 2) & 0xFFFF ) | ( this.sbuf[ 1 ] & 0xFF ) << 16;
        if ( size < ( Smb2Constants.SMB2_HEADER_LENGTH + 1 ) ) {
            throw new IOException("Invalid payload size: " + size);
        }

        if ( this.sbuf[ 0 ] != (byte) 0x00 || this.sbuf[ 4 ] != (byte) 0xFE || this.sbuf[ 5 ] != (byte) 'S' || this.sbuf[ 6 ] != (byte) 'M'
                || this.sbuf[ 7 ] != (byte) 'B' ) {
            throw new IOException("Houston we have a synchronization problem");
        }

        int nextCommand = Encdec.dec_uint32le(this.sbuf, 4 + 20);
        int maximumBufferSize = getContext().getConfig().getMaximumBufferSize();
        int msgSize = nextCommand != 0 ? nextCommand : size;
        if ( msgSize > maximumBufferSize ) {
            throw new IOException(String.format("Message size %d exceeds maxiumum buffer size %d", msgSize, maximumBufferSize));
        }

        ServerMessageBlock2Response cur = (ServerMessageBlock2Response) response;
        byte[] buffer = getContext().getBufferCache().getBuffer();
        try {
            int rl = nextCommand != 0 ? nextCommand : size;

            // read and decode first
            System.arraycopy(this.sbuf, 4, buffer, 0, Smb2Constants.SMB2_HEADER_LENGTH);
            readn(this.in, buffer, Smb2Constants.SMB2_HEADER_LENGTH, rl - Smb2Constants.SMB2_HEADER_LENGTH);

            int len = cur.decode(buffer, 0);

            if ( len > rl ) {
                throw new IOException(String.format("WHAT? ( read %d decoded %d ): %s", rl, len, cur));
            }
            else if ( nextCommand != 0 && len > nextCommand ) {
                throw new IOException("Overlapping commands");
            }
            size -= rl;

            while ( size > 0 && nextCommand != 0 ) {
                cur = (ServerMessageBlock2Response) cur.getNextResponse();
                if ( cur == null ) {
                    log.warn("Response not properly set up");
                    this.in.skip(size);
                    break;
                }

                // read next header
                readn(this.in, buffer, 0, Smb2Constants.SMB2_HEADER_LENGTH);
                nextCommand = Encdec.dec_uint32le(buffer, 20);

                if ( ( nextCommand != 0 && nextCommand > maximumBufferSize ) || ( nextCommand == 0 && size > maximumBufferSize ) ) {
                    throw new IOException(
                        String.format("Message size %d exceeds maxiumum buffer size %d", nextCommand != 0 ? nextCommand : size, maximumBufferSize));
                }

                rl = nextCommand != 0 ? nextCommand : size;

                if ( log.isDebugEnabled() ) {
                    log.debug(String.format("Compound next command %d read size %d remain %d", nextCommand, rl, size));
                }

                readn(this.in, buffer, Smb2Constants.SMB2_HEADER_LENGTH, rl - Smb2Constants.SMB2_HEADER_LENGTH);

                len = cur.decode(buffer, 0, true);
                if ( len > rl ) {
                    throw new IOException(String.format("WHAT? ( read %d decoded %d ): %s", rl, len, cur));
                }
                else if ( nextCommand != 0 && len > nextCommand ) {
                    throw new IOException("Overlapping commands");
                }
                size -= rl;
            }
        }
        finally {
            getContext().getBufferCache().releaseBuffer(buffer);
        }
    }


    /**
     * @param resp
     * @throws IOException
     * @throws SMBProtocolDecodingException
     */
    private void doRecvSMB1 ( CommonServerMessageBlock resp ) throws IOException, SMBProtocolDecodingException {
        byte[] buffer = getContext().getBufferCache().getBuffer();
        try {
            System.arraycopy(this.sbuf, 0, buffer, 0, 4 + SMB1_HEADER_LENGTH);
            int size = ( Encdec.dec_uint16be(buffer, 2) & 0xFFFF );
            if ( size < ( SMB1_HEADER_LENGTH + 1 ) || ( 4 + size ) > Math.min(0xFFFF, getContext().getConfig().getMaximumBufferSize()) ) {
                throw new IOException("Invalid payload size: " + size);
            }
            int errorCode = Encdec.dec_uint32le(buffer, 9) & 0xFFFFFFFF;
            if ( resp.getCommand() == ServerMessageBlock.SMB_COM_READ_ANDX && ( errorCode == 0 || errorCode == 0x80000005 ) ) {
                // overflow indicator normal for pipe
                SmbComReadAndXResponse r = (SmbComReadAndXResponse) resp;
                int off = SMB1_HEADER_LENGTH;
                /* WordCount thru dataOffset always 27 */
                readn(this.in, buffer, 4 + off, 27);
                off += 27;
                resp.decode(buffer, 4);
                /* EMC can send pad w/o data */
                int pad = r.getDataOffset() - off;
                if ( r.getByteCount() > 0 && pad > 0 && pad < 4 )
                    readn(this.in, buffer, 4 + off, pad);

                if ( r.getDataLength() > 0 ) {
                    readn(this.in, r.getData(), r.getOffset(), r.getDataLength()); /* read direct */
                }
            }
            else {
                readn(this.in, buffer, 4 + SMB1_HEADER_LENGTH, size - SMB1_HEADER_LENGTH);
                resp.decode(buffer, 4);
            }
        }
        finally {
            getContext().getBufferCache().releaseBuffer(buffer);
        }
    }


    @Override
    protected void doSkip ( Long key ) throws IOException {
        synchronized ( this.inLock ) {
            int size = Encdec.dec_uint16be(this.sbuf, 2) & 0xFFFF;
            if ( size < 33 || ( 4 + size ) > this.getContext().getConfig().getReceiveBufferSize() ) {
                /* log message? */
                log.warn("Flusing stream input");
                this.in.skip(this.in.available());
            }
            else {
                Response notification = createNotification(key);
                if ( notification != null ) {
                    log.debug("Parsing notification");
                    doRecv(notification);
                    handleNotification(notification);
                    return;
                }
                log.warn("Skipping message " + key);
                this.in.skip(size - 32);
            }
        }
    }


    /**
     * @param notification
     */
    protected void handleNotification ( Response notification ) {
        log.info("Received notification " + notification);
    }


    /**
     * @param key
     * @return
     * @throws SmbException
     */
    protected Response createNotification ( Long key ) throws SmbException {
        if ( key == null ) {
            // no valid header
            return null;
        }
        if ( this.smb2 ) {
            if ( key != -1 ) {
                return null;
            }
            int cmd = Encdec.dec_uint16le(this.sbuf, 4 + 12) & 0xFFFF;
            if ( cmd == 0x12 ) {
                return new Smb2OplockBreakNotification(getContext().getConfig());
            }
        }
        else {
            if ( key != 0xFFFF ) {
                return null;
            }
            int cmd = this.sbuf[ 4 + 4 ];
            if ( cmd == 0x24 ) {
                return new SmbComLockingAndX(getContext().getConfig());
            }
        }
        return null;
    }


    boolean checkStatus ( ServerMessageBlock req, ServerMessageBlock resp ) throws SmbException {
        boolean cont = false;
        if ( resp.getErrorCode() == 0x30002 ) {
            // if using DOS error codes this indicates a DFS referral
            resp.setErrorCode(NtStatus.NT_STATUS_PATH_NOT_COVERED);
        }
        else {
            resp.setErrorCode(SmbException.getStatusByCode(resp.getErrorCode()));
        }
        switch ( resp.getErrorCode() ) {
        case NtStatus.NT_STATUS_OK:
            cont = true;
            break;
        case NtStatus.NT_STATUS_ACCESS_DENIED:
        case NtStatus.NT_STATUS_WRONG_PASSWORD:
        case NtStatus.NT_STATUS_LOGON_FAILURE:
        case NtStatus.NT_STATUS_ACCOUNT_RESTRICTION:
        case NtStatus.NT_STATUS_INVALID_LOGON_HOURS:
        case NtStatus.NT_STATUS_INVALID_WORKSTATION:
        case NtStatus.NT_STATUS_PASSWORD_EXPIRED:
        case NtStatus.NT_STATUS_ACCOUNT_DISABLED:
        case NtStatus.NT_STATUS_ACCOUNT_LOCKED_OUT:
        case NtStatus.NT_STATUS_TRUSTED_DOMAIN_FAILURE:
            throw new SmbAuthException(resp.getErrorCode());
        case 0xC00000BB: // NT_STATUS_NOT_SUPPORTED
            throw new SmbUnsupportedOperationException();
        case NtStatus.NT_STATUS_PATH_NOT_COVERED:
            // samba fails to report the proper status for some operations
        case 0xC00000A2: // NT_STATUS_MEDIA_WRITE_PROTECTED
            checkReferral(resp, req.getPath(), req);
        case 0x80000005: /* STATUS_BUFFER_OVERFLOW */
            break; /* normal for DCERPC named pipes */
        case NtStatus.NT_STATUS_MORE_PROCESSING_REQUIRED:
            break; /* normal for NTLMSSP */
        default:
            if ( log.isDebugEnabled() ) {
                log.debug("Error code: 0x" + Hexdump.toHexString(resp.getErrorCode(), 8) + " for " + req.getClass().getSimpleName());
            }
            throw new SmbException(resp.getErrorCode(), null);
        }
        if ( resp.isVerifyFailed() ) {
            throw new SmbException("Signature verification failed.");
        }
        return cont;
    }


    /**
     * @param request
     * @param response
     * @throws SmbException
     */
    boolean checkStatus2 ( ServerMessageBlock2 req, Response resp ) throws SmbException {
        boolean cont = false;
        switch ( resp.getErrorCode() ) {
        case NtStatus.NT_STATUS_OK:
            cont = true;
            break;
        case NtStatus.NT_STATUS_PENDING:
            // must be the last
            cont = false;
            break;
        case NtStatus.NT_STATUS_ACCESS_DENIED:
        case NtStatus.NT_STATUS_WRONG_PASSWORD:
        case NtStatus.NT_STATUS_LOGON_FAILURE:
        case NtStatus.NT_STATUS_ACCOUNT_RESTRICTION:
        case NtStatus.NT_STATUS_INVALID_LOGON_HOURS:
        case NtStatus.NT_STATUS_INVALID_WORKSTATION:
        case NtStatus.NT_STATUS_PASSWORD_EXPIRED:
        case NtStatus.NT_STATUS_ACCOUNT_DISABLED:
        case NtStatus.NT_STATUS_ACCOUNT_LOCKED_OUT:
        case NtStatus.NT_STATUS_TRUSTED_DOMAIN_FAILURE:
            throw new SmbAuthException(resp.getErrorCode());
        case NtStatus.NT_STATUS_MORE_PROCESSING_REQUIRED:
            break; /* normal for SPNEGO */
        case 0x10B: // NT_STATUS_NOTIFY_CLEANUP
        case 0x10C:
            break;
        case 0xC00000BB: // NT_STATUS_NOT_SUPPORTED
            throw new SmbUnsupportedOperationException();
        case NtStatus.NT_STATUS_PATH_NOT_COVERED:
            if ( ! ( req instanceof RequestWithPath ) ) {
                throw new SmbException("Invalid request for a DFS NT_STATUS_PATH_NOT_COVERED response " + req.getClass().getName());
            }
            String path = ( (RequestWithPath) req ).getFullUNCPath();
            checkReferral(resp, path, ( (RequestWithPath) req ));
        default:
            if ( log.isDebugEnabled() ) {
                log.debug("Error code: 0x" + Hexdump.toHexString(resp.getErrorCode(), 8) + " for " + req.getClass().getSimpleName());
            }
            throw new SmbException(resp.getErrorCode(), null);
        }
        if ( resp.isVerifyFailed() ) {
            throw new SMBSignatureValidationException("Signature verification failed.");
        }
        return cont;
    }


    /**
     * @param resp
     * @param path
     * @param req
     * @throws SmbException
     * @throws DfsReferral
     */
    private void checkReferral ( Response resp, String path, RequestWithPath req ) throws SmbException, DfsReferral {
        DfsReferralData dr = null;
        if ( !getContext().getConfig().isDfsDisabled() ) {
            try {
                dr = getDfsReferrals(getContext(), path, req.getServer(), req.getDomain(), 1);
            }
            catch ( CIFSException e ) {
                throw new SmbException("Failed to get DFS referral", e);
            }
        }
        if ( dr == null ) {
            if ( log.isDebugEnabled() ) {
                log.debug("Error code: 0x" + Hexdump.toHexString(resp.getErrorCode(), 8));
            }
            throw new SmbException(resp.getErrorCode(), null);
        }

        if ( req.getDomain() != null && getContext().getConfig().isDfsConvertToFQDN() && dr instanceof DfsReferralDataImpl ) {
            ( (DfsReferralDataImpl) dr ).fixupDomain(req.getDomain());
        }
        if ( log.isDebugEnabled() ) {
            log.debug("Got referral " + dr);
        }

        getContext().getDfs().cache(getContext(), path, dr);
        throw new DfsReferral(dr);
    }


    <T extends CommonServerMessageBlockResponse> T send ( CommonServerMessageBlockRequest request, T response ) throws SmbException {
        return send(request, response, Collections.<RequestParam> emptySet());
    }


    <T extends CommonServerMessageBlockResponse> T send ( CommonServerMessageBlockRequest request, T response, Set<RequestParam> params )
            throws SmbException {
        ensureConnected(); /* must negotiate before we can test flags2, useUnicode, etc */
        if ( this.smb2 && ! ( request instanceof ServerMessageBlock2 ) ) {
            throw new SmbException("Not an SMB2 request " + request.getClass().getName());
        }
        else if ( !this.smb2 && ! ( request instanceof ServerMessageBlock ) ) {
            throw new SmbException("Not an SMB1 request");
        }

        this.negotiated.setupRequest(request);

        if ( response != null ) {
            request.setResponse(response); /* needed by sign */
            response.setDigest(request.getDigest());
        }

        try {
            if ( log.isTraceEnabled() ) {
                log.trace("Sending " + request);
            }
            if ( request.isCancel() ) {
                doSend0(request);
                return null;
            }
            else if ( request instanceof SmbComTransaction ) {
                response = sendComTransaction(request, response, params);
            }
            else {
                if ( response != null ) {
                    response.setCommand(request.getCommand());
                }
                response = sendrecv(request, response, params);
            }
        }
        catch ( SmbException se ) {
            throw se;
        }
        catch ( IOException ioe ) {
            throw new SmbException(ioe.getMessage(), ioe);
        }

        if ( log.isTraceEnabled() ) {
            log.trace("Response is " + response);
        }

        checkStatus(request, response);
        return response;
    }


    /**
     * @param request
     * @param response
     * @throws SmbException
     */
    private <T extends CommonServerMessageBlockResponse> boolean checkStatus ( CommonServerMessageBlockRequest request, T response )
            throws SmbException {
        CommonServerMessageBlockRequest cur = request;
        while ( cur != null ) {
            if ( this.smb2 ) {
                if ( !checkStatus2((ServerMessageBlock2) cur, cur.getResponse()) ) {
                    return false;
                }
            }
            else {
                if ( !checkStatus((ServerMessageBlock) cur, (ServerMessageBlock) cur.getResponse()) ) {
                    return false;
                }
            }
            cur = cur.getNext();
        }
        return true;
    }


    /**
     * @param request
     * @param response
     * @param params
     * @throws IOException
     * @throws SmbException
     * @throws TransportException
     * @throws EOFException
     */
    private <T extends CommonServerMessageBlock & Response> T sendComTransaction ( CommonServerMessageBlockRequest request, T response,
            Set<RequestParam> params ) throws IOException, SmbException, TransportException, EOFException {
        response.setCommand(request.getCommand());
        SmbComTransaction req = (SmbComTransaction) request;
        SmbComTransactionResponse resp = (SmbComTransactionResponse) response;
        resp.reset();

        long k;

        /*
         * First request w/ interim response
         */
        try {
            req.setBuffer(getContext().getBufferCache().getBuffer());
            req.nextElement();
            if ( req.hasMoreElements() ) {
                SmbComBlankResponse interim = new SmbComBlankResponse(getContext().getConfig());
                super.sendrecv(req, interim, params);
                if ( interim.getErrorCode() != 0 ) {
                    checkStatus(req, interim);
                }
                k = req.nextElement().getMid();
            }
            else {
                k = makeKey(req);
            }

            try {
                resp.clearReceived();
                long timeout = getResponseTimeout(req);
                if ( !params.contains(RequestParam.NO_TIMEOUT) ) {
                    resp.setExpiration(System.currentTimeMillis() + timeout);
                }
                else {
                    resp.setExpiration(null);
                }

                byte[] txbuf = getContext().getBufferCache().getBuffer();
                resp.setBuffer(txbuf);

                this.response_map.put(k, resp);

                /*
                 * Send multiple fragments
                 */

                do {
                    doSend0(req);
                }
                while ( req.hasMoreElements() && req.nextElement() != null );

                /*
                 * Receive multiple fragments
                 */
                synchronized ( resp ) {
                    while ( !resp.isReceived() || resp.hasMoreElements() ) {
                        if ( !params.contains(RequestParam.NO_TIMEOUT) ) {
                            resp.wait(timeout);
                            timeout = resp.getExpiration() - System.currentTimeMillis();
                            if ( timeout <= 0 ) {
                                throw new TransportException(this + " timedout waiting for response to " + req);
                            }
                        }
                        else {
                            resp.wait();
                            if ( log.isTraceEnabled() ) {
                                log.trace("Wait returned " + isDisconnected());
                            }
                            if ( isDisconnected() ) {
                                throw new EOFException("Transport closed while waiting for result");
                            }
                        }
                    }
                }

                if ( !resp.isReceived() ) {
                    throw new TransportException("Failed to read response");
                }

                if ( resp.getErrorCode() != 0 ) {
                    checkStatus(req, resp);
                }
                return response;
            }
            finally {
                this.response_map.remove(k);
            }
        }
        catch ( InterruptedException ie ) {
            throw new TransportException(ie);
        }
        finally {
            getContext().getBufferCache().releaseBuffer(req.releaseBuffer());
            getContext().getBufferCache().releaseBuffer(resp.releaseBuffer());
        }

    }


    @Override
    public String toString () {
        return super.toString() + "[" + this.address + ":" + this.port + ",state=" + this.state + ",signingEnforced=" + this.signingEnforced
                + ",usage=" + this.getUsageCount() + "]";
    }


    /* DFS */
    @Override
    public DfsReferralData getDfsReferrals ( CIFSContext ctx, String path, String targetHost, String targetDomain, int rn ) throws CIFSException {
        if ( log.isDebugEnabled() ) {
            log.debug("Resolving DFS path " + path);
        }

        if ( path.length() >= 2 && path.charAt(0) == '\\' && path.charAt(1) == '\\' ) {
            throw new SmbException("Path must not start with double slash: " + path);
        }

        try ( SmbSessionImpl sess = getSmbSession(ctx, targetHost, targetDomain);
              SmbTransportImpl transport = sess.getTransport();
              SmbTreeImpl ipc = sess.getSmbTree("IPC$", null) ) {

            DfsReferralRequestBuffer dfsReq = new DfsReferralRequestBuffer(path, 3);
            DfsReferralResponseBuffer dfsResp;
            if ( isSMB2() ) {
                Smb2IoctlRequest req = new Smb2IoctlRequest(ctx.getConfig(), Smb2IoctlRequest.FSCTL_DFS_GET_REFERRALS);
                req.setFlags(Smb2IoctlRequest.SMB2_O_IOCTL_IS_FSCTL);
                req.setInputData(dfsReq);
                dfsResp = ipc.send(req).getOutputData(DfsReferralResponseBuffer.class);
            }
            else {
                Trans2GetDfsReferralResponse resp = new Trans2GetDfsReferralResponse(ctx.getConfig());
                ipc.send(new Trans2GetDfsReferral(ctx.getConfig(), path), resp);
                dfsResp = resp.getDfsResponse();
            }

            if ( dfsResp.getNumReferrals() == 0 ) {
                return null;
            }
            else if ( rn == 0 || dfsResp.getNumReferrals() < rn ) {
                rn = dfsResp.getNumReferrals();
            }

            DfsReferralDataImpl cur = null;
            long expiration = System.currentTimeMillis() + ( ctx.getConfig().getDfsTtl() * 1000 );
            Referral[] refs = dfsResp.getReferrals();
            for ( int di = 0; di < rn; di++ ) {
                DfsReferralDataImpl dr = DfsReferralDataImpl.fromReferral(refs[ di ], path, expiration, dfsResp.getPathConsumed());
                dr.setDomain(targetDomain);

                if ( ( dfsResp.getTflags() & 0x2 ) == 0 && ( dr.getFlags() & 0x2 ) == 0 ) {
                    log.debug("Non-root referral is not final " + dfsResp);
                    dr.intermediate();
                }

                if ( cur == null ) {
                    cur = dr;
                }
                else {
                    cur.append(dr);
                    cur = dr;
                }
            }

            if ( log.isDebugEnabled() ) {
                log.debug("Got referral " + cur);
            }
            return cur;
        }
    }


    byte[] getPreauthIntegrityHash () {
        return this.preauthIntegrityHash;
    }


    private void updatePreauthHash ( byte[] input ) throws CIFSException {
        synchronized ( this.preauthIntegrityHash ) {
            this.preauthIntegrityHash = calculatePreauthHash(input, 0, input.length, this.preauthIntegrityHash);
        }
    }


    byte[] calculatePreauthHash ( byte[] input, int off, int len, byte[] oldHash ) throws CIFSException {
        if ( !this.smb2 || this.negotiated == null ) {
            throw new SmbUnsupportedOperationException();
        }

        Smb2NegotiateResponse resp = (Smb2NegotiateResponse) this.negotiated;
        if ( !resp.getSelectedDialect().atLeast(DialectVersion.SMB311) ) {
            throw new SmbUnsupportedOperationException();
        }

        MessageDigest dgst;
        switch ( resp.getSelectedPreauthHash() ) {
        case 1:
            dgst = Crypto.getSHA512();
            break;
        default:
            throw new SmbUnsupportedOperationException();
        }

        if ( oldHash != null ) {
            dgst.update(oldHash);
        }
        dgst.update(input, off, len);
        return dgst.digest();
    }


    Cipher createEncryptionCipher ( byte[] key ) throws CIFSException {
        if ( !this.smb2 || this.negotiated == null ) {
            throw new SmbUnsupportedOperationException();
        }

        Smb2NegotiateResponse resp = (Smb2NegotiateResponse) this.negotiated;
        int cipherId = -1;

        if ( resp.getSelectedDialect().atLeast(DialectVersion.SMB311) ) {
            cipherId = resp.getSelectedCipher();
        }
        else if ( resp.getSelectedDialect().atLeast(DialectVersion.SMB300) ) {
            cipherId = EncryptionNegotiateContext.CIPHER_AES128_CCM;
        }
        else {
            throw new SmbUnsupportedOperationException();
        }

        switch ( cipherId ) {
        case EncryptionNegotiateContext.CIPHER_AES128_CCM:
        case EncryptionNegotiateContext.CIPHER_AES128_GCM:
        default:
            throw new SmbUnsupportedOperationException();
        }
    }

    public int getRequestSecurityMode( Smb2NegotiateResponse first ) {
        int securityMode = Smb2Constants.SMB2_NEGOTIATE_SIGNING_ENABLED;
        if ( this.signingEnforced || ( first != null && first.isSigningRequired() ) ) {
            securityMode = Smb2Constants.SMB2_NEGOTIATE_SIGNING_REQUIRED | Smb2Constants.SMB2_NEGOTIATE_SIGNING_ENABLED;
        }
        
        return securityMode;
    }
}
