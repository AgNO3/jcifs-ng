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
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NoRouteToHostException;
import java.net.Socket;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;

import org.apache.log4j.Logger;

import jcifs.CIFSContext;
import jcifs.RuntimeCIFSException;
import jcifs.SmbConstants;
import jcifs.netbios.Name;
import jcifs.netbios.NbtException;
import jcifs.netbios.SessionRequestPacket;
import jcifs.netbios.SessionServicePacket;
import jcifs.netbios.UniAddress;
import jcifs.util.Encdec;
import jcifs.util.Hexdump;
import jcifs.util.transport.Request;
import jcifs.util.transport.Response;
import jcifs.util.transport.Transport;
import jcifs.util.transport.TransportException;


/**
 * 
 */
public class SmbTransport extends Transport implements SmbConstants {

    private static Logger log = Logger.getLogger(SmbTransport.class);

    class ServerData {

        byte sflags;
        int sflags2;
        int smaxMpxCount;
        int maxBufferSize;
        int sessKey;
        int scapabilities;
        String oemDomainName;
        int securityMode;
        int security;
        boolean encryptedPasswords;
        boolean signaturesEnabled;
        boolean signaturesRequired;
        int maxNumberVcs;
        int maxRawSize;
        long serverTime;
        int serverTimeZone;
        int encryptionKeyLength;
        byte[] encryptionKey;
        byte[] guid;
    }

    private final SmbComNegotiate NEGOTIATE_REQUEST;
    private boolean smb2 = false;
    InetAddress localAddr;
    int localPort;
    UniAddress address;
    Socket socket;
    int port, mid;
    OutputStream out;
    InputStream in;
    byte[] sbuf = new byte[512]; /* small local buffer */
    SmbComBlankResponse key;
    long sessionExpiration;
    SigningDigest digest = null;
    List<SmbSession> sessions = new LinkedList<>();
    ServerData server = new ServerData();
    /* Negotiated values */
    int flags2;
    int maxMpxCount;
    int snd_buf_size;
    int rcv_buf_size;
    int capabilities;
    int sessionKey = 0x00000000;
    boolean useUnicode;
    String tconHostName = null;

    private CIFSContext transportContext;

    private Object socketLock = new Object();


    SmbTransport ( CIFSContext tc, SmbComNegotiate nego, UniAddress address, int port, InetAddress localAddr, int localPort ) {
        this.transportContext = tc;
        this.key = new SmbComBlankResponse(tc.getConfig());
        this.NEGOTIATE_REQUEST = nego;
        this.flags2 = this.NEGOTIATE_REQUEST.flags2;
        this.sessionExpiration = System.currentTimeMillis() + tc.getConfig().getSessionTimeout();
        this.capabilities = tc.getConfig().getCapabilities();
        this.address = address;
        this.port = port;
        this.localAddr = localAddr;
        this.localPort = localPort;

        this.maxMpxCount = tc.getConfig().getMaxMpxCount();
        this.snd_buf_size = tc.getConfig().getSendBufferSize();
        this.rcv_buf_size = tc.getConfig().getRecieveBufferSize();
        this.useUnicode = tc.getConfig().isUseUnicode();

    }


    SmbComNegotiate getNegotiateRequest () {
        return this.NEGOTIATE_REQUEST;
    }


    /**
     * @return the context associated with this transport connection
     */
    public CIFSContext getTransportContext () {
        return this.transportContext;
    }


    /**
     * @return the server's encryption key
     */
    public byte[] getServerEncryptionKey () {
        if ( this.server == null ) {
            return null;
        }
        return this.server.encryptionKey;
    }


    /**
     * 
     * @param tf
     *            context to use
     * @return a session for the context
     */
    public synchronized SmbSession getSmbSession ( CIFSContext tf ) {
        SmbSession ssn;
        long now;

        if ( log.isTraceEnabled() ) {
            log.trace("Currently " + this.sessions.size() + " session(s) active for " + this);
        }

        ListIterator<SmbSession> iter = this.sessions.listIterator();
        while ( iter.hasNext() ) {
            ssn = iter.next();
            if ( ssn.matches(tf) ) {
                if ( log.isTraceEnabled() ) {
                    log.trace("Reusing existing session " + ssn);
                }
                return ssn;
            }
            else if ( log.isTraceEnabled() ) {
                log.trace("Existing session " + ssn + " does not match " + tf.getCredentials());
            }
        }

        /* logoff old sessions */
        if ( tf.getConfig().getSessionTimeout() > 0 && this.sessionExpiration < ( now = System.currentTimeMillis() ) ) {
            this.sessionExpiration = now + tf.getConfig().getSoTimeout();
            iter = this.sessions.listIterator();
            while ( iter.hasNext() ) {
                ssn = iter.next();
                if ( ssn.getExpiration() != null && ssn.getExpiration() < now ) {
                    if ( log.isDebugEnabled() ) {
                        log.debug("Closing session after timeout " + ssn);
                    }
                    ssn.logoff(false);
                }
            }
        }
        ssn = new SmbSession(tf, this, this.address, this.port, this.localAddr, this.localPort);
        if ( log.isDebugEnabled() ) {
            log.debug("Establishing new session " + ssn);
        }
        this.sessions.add(ssn);
        return ssn;
    }


    boolean matches ( UniAddress addr, int prt, InetAddress laddr, int lprt, String hostName ) {
        if ( hostName == null )
            hostName = addr.getHostName();
        return ( this.tconHostName == null || hostName.equalsIgnoreCase(this.tconHostName) ) && addr.equals(this.address)
                && ( prt == 0 || prt == this.port ||
                        /* port 139 is ok if 445 was requested */
                        ( prt == 445 && this.port == 139 ) )
                && ( laddr == this.localAddr || ( laddr != null && laddr.equals(this.localAddr) ) ) && lprt == this.localPort;
    }


    /**
     * @param cap
     * @return whether the given capability was negotiated
     * @throws SmbException
     */
    public boolean hasCapability ( int cap ) throws SmbException {
        try {
            connect(this.transportContext.getConfig().getResponseTimeout());
        }
        catch ( IOException ioe ) {
            throw new SmbException(ioe.getMessage(), ioe);
        }
        return ( this.capabilities & cap ) == cap;
    }


    boolean isSignatureSetupRequired () {
        return ( this.transportContext.getConfig().isSigningEnforced() || ( this.flags2 & SmbConstants.FLAGS2_SECURITY_SIGNATURES ) != 0 )
                && this.digest == null;
    }


    void ssn139 () throws IOException {
        Name calledName = new Name(this.transportContext.getConfig(), this.address.firstCalledName(), 0x20, null);
        do {
            this.socket = new Socket();
            if ( this.localAddr != null )
                this.socket.bind(new InetSocketAddress(this.localAddr, this.localPort));
            this.socket.connect(new InetSocketAddress(this.address.getHostAddress(), 139), this.transportContext.getConfig().getConnTimeout());
            this.socket.setSoTimeout(this.transportContext.getConfig().getSoTimeout());

            this.out = this.socket.getOutputStream();
            this.in = this.socket.getInputStream();

            SessionServicePacket ssp = new SessionRequestPacket(calledName, this.transportContext.getNameServiceClient().getLocalName());
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
                if ( log.isDebugEnabled() )
                    log.debug("session established ok with " + this.address);
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
        while ( ( calledName.name = this.address.nextCalledName(this.getTransportContext()) ) != null );

        throw new IOException("Failed to establish session with " + this.address);
    }


    private SmbComNegotiateResponse negotiate ( int prt ) throws IOException {
        /*
         * We cannot use Transport.sendrecv() yet because
         * the Transport thread is not setup until doConnect()
         * returns and we want to supress all communication
         * until we have properly negotiated.
         */
        synchronized ( this.sbuf ) {
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

            if ( ++this.mid == 32000 )
                this.mid = 1;
            this.NEGOTIATE_REQUEST.mid = this.mid;
            int n = this.NEGOTIATE_REQUEST.encode(this.sbuf, 4);
            Encdec.enc_uint32be(n & 0xFFFF, this.sbuf, 0); /* 4 byte ssn msg header */

            if ( log.isTraceEnabled() ) {
                log.trace(this.NEGOTIATE_REQUEST);
                log.trace(Hexdump.toHexString(this.sbuf, 4, n));
            }

            this.out.write(this.sbuf, 0, 4 + n);
            this.out.flush();
            /*
             * Note the Transport thread isn't running yet so we can
             * read from the socket here.
             */
            if ( peekKey() == null ) /* try to read header */
                throw new IOException("transport closed in negotiate");
            int size = Encdec.dec_uint16be(this.sbuf, 2) & 0xFFFF;
            if ( size < 33 || ( 4 + size ) > this.sbuf.length ) {
                throw new IOException("Invalid payload size: " + size);
            }
            readn(this.in, this.sbuf, 4 + 32, size - 32);

            SmbComNegotiateResponse resp;

            if ( !this.smb2 ) {
                resp = new SmbComNegotiateResponse(this.getTransportContext().getConfig(), this.server);
            }
            else {
                throw new RuntimeCIFSException("SMB2 not yet supported");
            }

            resp.decode(this.sbuf, 4);

            if ( log.isTraceEnabled() ) {
                log.trace(resp);
                log.trace(Hexdump.toHexString(this.sbuf, 4, n));
            }

            return resp;
        }
    }


    /**
     * Connect the transport
     * 
     * @throws SmbException
     */
    public void connect () throws SmbException {
        try {
            super.connect(this.transportContext.getConfig().getResponseTimeout());
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
        log.debug("Connecting in state " + this.state);

        SmbComNegotiateResponse resp;
        try {
            resp = negotiate(this.port);
        }
        catch ( ConnectException ce ) {
            this.port = ( this.port == 0 || this.port == DEFAULT_PORT ) ? 139 : DEFAULT_PORT;
            resp = negotiate(this.port);
        }
        catch ( NoRouteToHostException nr ) {
            this.port = ( this.port == 0 || this.port == DEFAULT_PORT ) ? 139 : DEFAULT_PORT;
            resp = negotiate(this.port);
        }

        if ( resp.dialectIndex > 10 ) {
            throw new SmbException("This client does not support the negotiated dialect.");
        }
        if ( ( this.server.scapabilities & CAP_EXTENDED_SECURITY ) != CAP_EXTENDED_SECURITY && this.server.encryptionKeyLength != 8
                && this.getTransportContext().getConfig().getLanManCompatibility() == 0 ) {
            throw new SmbException("Unexpected encryption key length: " + this.server.encryptionKeyLength);
        }

        /* Adjust negotiated values */
        this.tconHostName = this.address.getHostName();
        if ( this.getTransportContext().getConfig().isSigningEnforced() && !this.server.signaturesEnabled ) {
            throw new SmbException("Signatures are requried but the server does not support them");
        }
        else if ( this.getTransportContext().getConfig().isSigningEnforced() || this.server.signaturesRequired
                || ( this.server.signaturesEnabled && this.getTransportContext().getConfig().isSigningEnabled() ) ) {
            this.flags2 |= SmbConstants.FLAGS2_SECURITY_SIGNATURES;
            if ( this.getTransportContext().getConfig().isSigningEnforced() ) {
                this.flags2 |= SmbConstants.FLAGS2_SECURITY_REQUIRE_SIGNATURES;
            }
        }
        else {
            this.flags2 &= 0xFFFF ^ SmbConstants.FLAGS2_SECURITY_SIGNATURES;
        }

        this.maxMpxCount = Math.min(this.maxMpxCount, this.server.smaxMpxCount);
        if ( this.maxMpxCount < 1 )
            this.maxMpxCount = 1;
        this.snd_buf_size = Math.min(this.snd_buf_size, this.server.maxBufferSize);
        this.capabilities &= this.server.scapabilities;
        if ( ( this.server.scapabilities & CAP_EXTENDED_SECURITY ) == CAP_EXTENDED_SECURITY )
            this.capabilities |= CAP_EXTENDED_SECURITY; // & doesn't copy high bit

        if ( this.getTransportContext().getConfig().isUseUnicode() || this.getTransportContext().getConfig().isForceUnicode() ) {
            this.capabilities |= SmbConstants.CAP_UNICODE;
        }

        if ( ( this.capabilities & SmbConstants.CAP_UNICODE ) == 0 ) {
            // server doesn't want unicode
            if ( this.getTransportContext().getConfig().isForceUnicode() ) {
                this.capabilities |= SmbConstants.CAP_UNICODE;
                this.useUnicode = true;
            }
            else {
                this.useUnicode = false;
                this.flags2 &= 0xFFFF ^ SmbConstants.FLAGS2_UNICODE;
            }
        }
        else {
            this.useUnicode = this.getTransportContext().getConfig().isUseUnicode();
        }

        if ( this.useUnicode ) {
            log.debug("Unicode is enabled");
        }
        else {
            log.debug("Unicode is disabled");
        }
    }


    @Override
    protected synchronized void doDisconnect ( boolean hard ) throws IOException {
        ListIterator<SmbSession> iter = this.sessions.listIterator();

        if ( log.isDebugEnabled() ) {
            log.debug("Disconnecting transport " + this);
        }

        try {
            if ( log.isTraceEnabled() ) {
                log.trace("Currently " + this.sessions.size() + " session(s) active for " + this);
            }
            while ( iter.hasNext() ) {
                SmbSession ssn = iter.next();
                try {
                    ssn.logoff(hard);
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
            this.digest = null;
            this.socket = null;
            this.tconHostName = null;
            this.transportContext.getTransportPool().removeTransport(this);
        }
    }


    @Override
    protected void makeKey ( Request request ) throws IOException {
        /* The request *is* the key */
        if ( ++this.mid == 32000 )
            this.mid = 1;
        ( (ServerMessageBlock) request ).mid = this.mid;
    }


    @Override
    protected Request peekKey () throws IOException {
        do {
            if ( ( readn(this.in, this.sbuf, 0, 4) ) < 4 )
                return null;
        }
        while ( this.sbuf[ 0 ] == (byte) 0x85 ); /* Dodge NetBIOS keep-alive */
        /* read smb header */
        if ( ( readn(this.in, this.sbuf, 4, 32) ) < 32 )
            return null;

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

            if ( this.sbuf[ 0 ] == (byte) 0x00 && this.sbuf[ 1 ] == (byte) 0x00 && ( this.sbuf[ 4 ] == (byte) 0xFF || this.sbuf[ 4 ] == (byte) 0xFE )
                    && this.sbuf[ 5 ] == (byte) 'S' && this.sbuf[ 6 ] == (byte) 'M' && this.sbuf[ 7 ] == (byte) 'B' ) {
                if ( this.sbuf[ 4 ] == (byte) 0xFE ) {
                    this.smb2 = true;
                }
                break; /* all good */
            }
            /* out of phase maybe? */
            /* inch forward 1 byte and try again */
            for ( int i = 0; i < 35; i++ ) {
                this.sbuf[ i ] = this.sbuf[ i + 1 ];
            }
            int b;
            if ( ( b = this.in.read() ) == -1 )
                return null;
            this.sbuf[ 35 ] = (byte) b;
        }

        this.key.mid = Encdec.dec_uint16le(this.sbuf, 34) & 0xFFFF;

        /*
         * Unless key returned is null or invalid Transport.loop() always
         * calls doRecv() after and no one else but the transport thread
         * should call doRecv(). Therefore it is ok to expect that the data
         * in sbuf will be preserved for copying into BUF in doRecv().
         */

        return this.key;
    }


    @Override
    protected void doSend ( Request request ) throws IOException {

        ServerMessageBlock smb = (ServerMessageBlock) request;
        byte[] buffer = this.getTransportContext().getBufferCache().getBuffer();
        try {
            int n = smb.encode(buffer, 4);
            Encdec.enc_uint32be(n & 0xFFFF, buffer, 0); /* 4 byte session message header */
            if ( log.isTraceEnabled() ) {
                do {
                    log.trace(smb);
                }
                while ( smb instanceof AndXServerMessageBlock && ( smb = ( (AndXServerMessageBlock) smb ).andx ) != null );
                log.trace(Hexdump.toHexString(buffer, 4, n));

            }
            /*
             * For some reason this can sometimes get broken up into another
             * "NBSS Continuation Message" frame according to WireShark
             */
            synchronized ( this.socketLock ) {
                this.out.write(buffer, 0, 4 + n);
            }
        }
        finally {
            this.getTransportContext().getBufferCache().releaseBuffer(buffer);
        }
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


    @Override
    protected void doRecv ( Response response ) throws IOException {
        ServerMessageBlock resp = (ServerMessageBlock) response;
        resp.useUnicode = this.useUnicode;
        byte[] buffer = this.getTransportContext().getBufferCache().getBuffer();
        try {
            int size;
            synchronized ( this.socketLock ) {
                System.arraycopy(this.sbuf, 0, buffer, 0, 4 + HEADER_LENGTH);
                size = Encdec.dec_uint16be(buffer, 2) & 0xFFFF;
                if ( size < ( HEADER_LENGTH + 1 ) || ( 4 + size ) > this.rcv_buf_size ) {
                    throw new IOException("Invalid payload size: " + size);
                }
                int errorCode = Encdec.dec_uint32le(buffer, 9) & 0xFFFFFFFF;
                if ( resp.command == ServerMessageBlock.SMB_COM_READ_ANDX && ( errorCode == 0 || errorCode == 0x80000005 ) ) {
                    // overflow indicator normal for pipe

                    SmbComReadAndXResponse r = (SmbComReadAndXResponse) resp;
                    int off = HEADER_LENGTH;
                    /* WordCount thru dataOffset always 27 */
                    readn(this.in, buffer, 4 + off, 27);
                    off += 27;
                    try {
                        resp.decode(buffer, 4);
                    }
                    catch ( Exception e ) {
                        resp.isError = true;
                        throw e;
                    }
                    /* EMC can send pad w/o data */
                    int pad = r.dataOffset - off;
                    if ( r.byteCount > 0 && pad > 0 && pad < 4 )
                        readn(this.in, buffer, 4 + off, pad);

                    if ( r.dataLength > 0 ) {
                        readn(this.in, r.b, r.off, r.dataLength); /* read direct */
                    }
                }
                else {
                    readn(this.in, buffer, 4 + 32, size - 32);
                    resp.decode(buffer, 4);
                    if ( resp instanceof SmbComTransactionResponse ) {
                        ( (SmbComTransactionResponse) resp ).nextElement();
                    }
                }
            }

            /*
             * Verification fails (w/ W2K3 server at least) if status is not 0. This
             * suggests MS doesn't compute the signature (correctly) for error responses
             * (perhaps for DOS reasons).
             */
            if ( this.digest != null && resp.errorCode == 0 ) {
                this.digest.verify(buffer, 4, resp);
            }

            if ( log.isTraceEnabled() ) {
                log.trace(response);
                log.trace(Hexdump.toHexString(buffer, 4, size));
            }
        }
        catch ( Exception e ) {
            resp.isError = true;
            throw e;
        }
        finally {
            this.getTransportContext().getBufferCache().releaseBuffer(buffer);
        }
    }


    @Override
    protected void doSkip () throws IOException {
        int size = Encdec.dec_uint16be(this.sbuf, 2) & 0xFFFF;
        if ( size < 33 || ( 4 + size ) > this.rcv_buf_size ) {
            /* log message? */
            this.in.skip(this.in.available());
        }
        else {
            this.in.skip(size - 32);
        }
    }


    void checkStatus ( ServerMessageBlock req, ServerMessageBlock resp ) throws SmbException {
        if ( resp.errorCode == 0x30002 ) {
            // if using DOS error codes this indicates a DFS referral
            resp.errorCode = NtStatus.NT_STATUS_PATH_NOT_COVERED;
        }
        else {
            resp.errorCode = SmbException.getStatusByCode(resp.errorCode);
        }
        switch ( resp.errorCode ) {
        case NtStatus.NT_STATUS_OK:
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
            throw new SmbAuthException(resp.errorCode);
        case NtStatus.NT_STATUS_PATH_NOT_COVERED:
            // samba fails to report the proper status for some operations
        case 0xC00000A2: // NT_STATUS_MEDIA_WRITE_PROTECTED
            DfsReferral dr = null;
            if ( !this.getTransportContext().getConfig().isDfsDisabled() ) {
                dr = getDfsReferrals(getTransportContext(), req.path, 1);
            }
            if ( dr == null ) {
                log.debug("Error code: 0x" + Hexdump.toHexString(resp.errorCode, 8));
                throw new SmbException(resp.errorCode, null);
            }

            if ( log.isDebugEnabled() ) {
                log.debug("Got referral " + dr);
            }
            this.getTransportContext().getDfs().cache(req.path, dr, getTransportContext());
            throw dr;
        case 0x80000005: /* STATUS_BUFFER_OVERFLOW */
            break; /* normal for DCERPC named pipes */
        case NtStatus.NT_STATUS_MORE_PROCESSING_REQUIRED:
            break; /* normal for NTLMSSP */
        default:
            log.debug("Error code: 0x" + Hexdump.toHexString(resp.errorCode, 8) + " for " + req.getClass().getSimpleName());
            throw new SmbException(resp.errorCode, null);
        }
        if ( resp.verifyFailed ) {
            throw new SmbException("Signature verification failed.");
        }
    }


    void send ( ServerMessageBlock request, ServerMessageBlock response, boolean doTimeout ) throws SmbException {

        connect(); /* must negotiate before we can test flags2, useUnicode, etc */

        request.flags2 |= this.flags2;
        request.useUnicode = this.useUnicode;
        request.response = response; /* needed by sign */
        if ( request.digest == null )
            request.digest = this.digest; /* for sign called in encode */

        try {
            if ( log.isTraceEnabled() ) {
                log.trace("Sending " + request);
            }
            if ( response == null ) {
                doSend0(request);
                return;
            }
            else if ( request instanceof SmbComTransaction ) {
                response.command = request.command;
                SmbComTransaction req = (SmbComTransaction) request;
                SmbComTransactionResponse resp = (SmbComTransactionResponse) response;

                req.maxBufferSize = this.snd_buf_size;
                resp.reset();

                try {
                    setupBuffers(req, resp);

                    /*
                     * First request w/ interim response
                     */

                    req.nextElement();
                    if ( req.hasMoreElements() ) {
                        SmbComBlankResponse interim = new SmbComBlankResponse(getTransportContext().getConfig());
                        super.sendrecv(req, interim, doTimeout ? (long) this.transportContext.getConfig().getResponseTimeout() : null);
                        if ( interim.errorCode != 0 ) {
                            checkStatus(req, interim);
                        }
                        req.nextElement();
                    }
                    else {
                        makeKey(req);
                    }

                    synchronized ( this ) {
                        response.received = false;
                        resp.isReceived = false;
                        try {
                            this.response_map.put(req, resp);

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

                            long timeout = this.transportContext.getConfig().getResponseTimeout();
                            if ( doTimeout ) {
                                resp.expiration = System.currentTimeMillis() + timeout;
                            }
                            else {
                                resp.expiration = null;
                            }
                            while ( resp.hasMoreElements() ) {
                                if ( doTimeout ) {
                                    wait(timeout);
                                    timeout = resp.expiration - System.currentTimeMillis();
                                    if ( timeout <= 0 ) {
                                        throw new TransportException(this + " timedout waiting for response to " + req);
                                    }
                                }
                                else {
                                    wait();
                                    if ( log.isTraceEnabled() ) {
                                        log.trace("Wait returned " + this.isDisconnected());
                                    }
                                    if ( this.isDisconnected() ) {
                                        throw new EOFException("Transport closed while waiting for result");
                                    }
                                }
                            }

                            if ( response.errorCode != 0 ) {
                                checkStatus(req, resp);
                            }
                        }
                        catch ( InterruptedException ie ) {
                            throw new TransportException(ie);
                        }
                        finally {
                            this.response_map.remove(req);
                        }
                    }
                }
                finally {
                    this.getTransportContext().getBufferCache().releaseBuffer(req.txn_buf);
                    this.getTransportContext().getBufferCache().releaseBuffer(resp.txn_buf);
                }

            }
            else {
                response.command = request.command;
                super.sendrecv(request, response, doTimeout ? (long) this.transportContext.getConfig().getResponseTimeout() : null);
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
    }


    void setupBuffers ( SmbComTransaction req, SmbComTransactionResponse rsp ) {
        req.txn_buf = getTransportContext().getBufferCache().getBuffer();
        rsp.txn_buf = getTransportContext().getBufferCache().getBuffer();
    }


    @Override
    public String toString () {
        return super.toString() + "[" + this.address + ":" + this.port + "]";
    }


    /* DFS */
    DfsReferral getDfsReferrals ( CIFSContext ctx, String path, int rn ) throws SmbException {
        if ( log.isDebugEnabled() ) {
            log.debug("Resolving DFS path " + path);
        }
        SmbSession sess = getSmbSession(ctx);
        SmbTree ipc = sess.getSmbTree("IPC$", null);
        Trans2GetDfsReferralResponse resp = new Trans2GetDfsReferralResponse(ctx.getConfig());

        ipc.send(new Trans2GetDfsReferral(ctx.getConfig(), path), resp);

        if ( resp.numReferrals == 0 ) {
            return null;
        }
        else if ( rn == 0 || resp.numReferrals < rn ) {
            rn = resp.numReferrals;
        }

        DfsReferral dr = new DfsReferral();

        String[] arr = new String[4];
        long expiration = System.currentTimeMillis() + ( ctx.getConfig().getDfsTtl() * 1000 );

        int di = 0;
        for ( ;; ) {
            /*
             * NTLM HTTP Authentication must be re-negotiated
             * with challenge from 'server' to access DFS vol.
             */
            if ( ctx.getCredentials() instanceof NtlmPasswordAuthentication ) {
                dr.resolveHashes = ( (NtlmPasswordAuthentication) ctx.getCredentials() ).areHashesExternal();
            }
            dr.ttl = resp.referrals[ di ].ttl;
            dr.expiration = expiration;
            if ( path.equals("") ) {
                dr.server = resp.referrals[ di ].rpath.substring(1).toLowerCase();
            }
            else {
                dfsPathSplit(resp.referrals[ di ].node, arr);
                dr.server = arr[ 1 ];
                dr.share = arr[ 2 ];
                dr.path = arr[ 3 ];
            }
            dr.pathConsumed = resp.pathConsumed;

            di++;
            if ( di == rn )
                break;

            dr.append(new DfsReferral());
            dr = dr.next;
        }

        if ( log.isDebugEnabled() ) {
            log.debug("Got referral " + dr);
        }
        return dr.next;
    }


    /*
     * Split DFS path like \fs1.example.com\root5\link2\foo\bar.txt into at
     * most 3 components (not including the first index which is always empty):
     * result[0] = ""
     * result[1] = "fs1.example.com"
     * result[2] = "root5"
     * result[3] = "link2\foo\bar.txt"
     */
    void dfsPathSplit ( String path, String[] result ) {
        int ri = 0, rlast = result.length - 1;
        int i = 0, b = 0, len = path.length();

        do {
            if ( ri == rlast ) {
                result[ rlast ] = path.substring(b);
                return;
            }
            if ( i == len || path.charAt(i) == '\\' ) {
                result[ ri++ ] = path.substring(b, i);
                b = i + 1;
            }
        }
        while ( i++ < len );

        while ( ri < result.length ) {
            result[ ri++ ] = "";
        }
    }

}
