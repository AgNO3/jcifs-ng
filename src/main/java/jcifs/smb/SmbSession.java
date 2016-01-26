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
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import javax.security.auth.Subject;

import org.apache.log4j.Logger;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.SmbConstants;
import jcifs.UniAddress;
import jcifs.netbios.NbtAddress;


public final class SmbSession {

    private static final Logger log = Logger.getLogger(SmbSession.class);

    static NbtAddress[] dc_list = null;
    static long dc_list_expiration;
    static int dc_list_counter;


    private static NtlmChallenge interrogate ( CIFSContext tf, NbtAddress addr ) throws SmbException {
        UniAddress dc = new UniAddress(addr);
        SmbTransport trans = tf.getTransportPool().getSmbTransport(tf, dc, 0);
        if ( !tf.hasDefaultCredentials() ) {
            trans.connect();
            log.warn(
                "Default credentials (jcifs.smb.client.username/password)" + " not specified. SMB signing may not work propertly."
                        + "  Skipping DC interrogation.");
        }
        else {
            SmbSession ssn = trans.getSmbSession(tf.withDefaultCredentials());
            ssn.getSmbTree(tf.getConfig().getLogonShare(), null).treeConnect(null, null);
        }
        return new NtlmChallenge(trans.server.encryptionKey, dc);
    }


    public synchronized static NtlmChallenge getChallengeForDomain ( CIFSContext tc, String domain ) throws SmbException, UnknownHostException {
        if ( domain == null ) {
            throw new SmbException("A domain was not specified");
        }
        long now = System.currentTimeMillis();
        int retry = 1;

        do {
            if ( dc_list_expiration < now ) {
                NbtAddress[] list = NbtAddress.getAllByName(domain, 0x1C, null, null, tc);
                dc_list_expiration = now + tc.getConfig().getNetbiosCacheTimeout() * 1000L;
                if ( list != null && list.length > 0 ) {
                    dc_list = list;
                }
                else { /* keep using the old list */
                    dc_list_expiration = now + 1000 * 60 * 15; /* 15 min */
                    log.warn("Failed to retrieve DC list from WINS");
                }
            }

            int max = Math.min(dc_list.length, tc.getConfig().getNetbiosLookupRespLimit());
            for ( int j = 0; j < max; j++ ) {
                int i = dc_list_counter++ % max;
                if ( dc_list[ i ] != null ) {
                    try {
                        return interrogate(tc, dc_list[ i ]);
                    }
                    catch ( SmbException se ) {
                        log.warn("Failed validate DC: " + dc_list[ i ], se);
                    }
                    dc_list[ i ] = null;
                }
            }

            /*
             * No DCs found, for retieval of list by expiring it and retry.
             */
            dc_list_expiration = 0;
        }
        while ( retry-- > 0 );

        dc_list_expiration = now + 1000 * 60 * 15; /* 15 min */
        throw new UnknownHostException("Failed to negotiate with a suitable domain controller for " + domain);
    }


    public static byte[] getChallenge ( UniAddress dc, CIFSContext tf ) throws SmbException {
        return getChallenge(dc, 0, tf);
    }


    public static byte[] getChallenge ( UniAddress dc, int port, CIFSContext tf ) throws SmbException {
        SmbTransport trans = tf.getTransportPool().getSmbTransport(tf, dc, port);
        trans.connect();
        return trans.server.encryptionKey;
    }


    /**
     * Authenticate arbitrary credentials represented by the
     * <tt>NtlmPasswordAuthentication</tt> object against the domain controller
     * specified by the <tt>UniAddress</tt> parameter. If the credentials are
     * not accepted, an <tt>SmbAuthException</tt> will be thrown. If an error
     * occurs an <tt>SmbException</tt> will be thrown. If the credentials are
     * valid, the method will return without throwing an exception. See the
     * last <a href="../../../faq.html">FAQ</a> question.
     * <p>
     * See also the <tt>jcifs.smb.client.logonShare</tt> property.
     */
    public static void logon ( UniAddress dc, CIFSContext tf ) throws SmbException {
        logon(dc, 0, tf);
    }


    public static void logon ( UniAddress dc, int port, CIFSContext tf ) throws SmbException {
        SmbTransport smbTransport = tf.getTransportPool().getSmbTransport(tf, dc, port);
        SmbSession smbSession = smbTransport.getSmbSession(tf);
        SmbTree tree = smbSession.getSmbTree(tf.getConfig().getLogonShare(), null);
        if ( tf.getConfig().getLogonShare() == null ) {
            tree.treeConnect(null, null);
        }
        else {
            Trans2FindFirst2 req = new Trans2FindFirst2(tree.session.getConfig(), "\\", "*", SmbFile.ATTR_DIRECTORY);
            Trans2FindFirst2Response resp = new Trans2FindFirst2Response(tree.session.getConfig());
            tree.send(req, resp);
        }
    }

    /*
     * 0 - not connected
     * 1 - connecting
     * 2 - connected
     * 3 - disconnecting
     */
    private int connectionState;
    private int uid;
    private List<SmbTree> trees;
    // Transport parameters allows trans to be removed from CONNECTIONS
    private UniAddress address;
    private int port, localPort;
    private InetAddress localAddr;

    private SmbTransport transport = null;
    private long expiration;
    private String netbiosName = null;

    private CIFSContext transportContext;

    private SmbCredentials credentials;
    private byte[] sessionKey;


    SmbSession ( CIFSContext tf, SmbTransport transport, UniAddress address, int port, InetAddress localAddr, int localPort ) {
        this.transportContext = tf;
        this.transport = transport;
        this.address = address;
        this.port = port;
        this.localAddr = localAddr;
        this.localPort = localPort;
        this.trees = new ArrayList<>();
        this.connectionState = 0;
        this.credentials = tf.getCredentials().clone();
    }


    /**
     * @return
     */
    public Configuration getConfig () {
        return this.transportContext.getConfig();
    }


    /**
     * @return the sessionKey
     */
    public byte[] getSessionKey () throws CIFSException {
        if ( this.sessionKey == null ) {
            throw new CIFSException("No session key available");
        }
        return this.sessionKey;
    }


    synchronized SmbTree getSmbTree ( String share, String service ) {
        if ( share == null ) {
            share = "IPC$";
        }
        for ( SmbTree t : this.trees ) {
            if ( t.matches(share, service) ) {
                return t;
            }
        }
        SmbTree t = new SmbTree(this, share, service);
        this.trees.add(t);
        return t;
    }


    /**
     * @param tf
     * @return
     */
    protected boolean matches ( CIFSContext tf ) {
        return Objects.equals(this.getCredentials(), tf.getCredentials());
    }


    synchronized SmbTransport transport () {
        if ( this.transport == null ) {
            this.transport = this.transportContext.getTransportPool()
                    .getSmbTransport(this.transportContext, this.address, this.port, this.localAddr, this.localPort, null);
        }
        return this.transport;
    }


    void send ( ServerMessageBlock request, ServerMessageBlock response ) throws SmbException {
        synchronized ( transport() ) {
            if ( response != null ) {
                response.received = false;
            }

            this.expiration = System.currentTimeMillis() + this.transportContext.getConfig().getSoTimeout();
            try {
                sessionSetup(request, response);
            }
            catch ( GeneralSecurityException e ) {
                throw new SmbException("Session setup failed", e);
            }

            if ( response != null && response.received ) {
                return;
            }

            if ( request instanceof SmbComTreeConnectAndX ) {
                SmbComTreeConnectAndX tcax = (SmbComTreeConnectAndX) request;
                if ( this.netbiosName != null && tcax.path.endsWith("\\IPC$") ) {
                    /*
                     * Some pipes may require that the hostname in the tree connect
                     * be the netbios name. So if we have the netbios server name
                     * from the NTLMSSP type 2 message, and the share is IPC$, we
                     * assert that the tree connect path uses the netbios hostname.
                     */
                    tcax.path = "\\\\" + this.netbiosName + "\\IPC$";
                }
            }

            request.uid = this.uid;
            try {
                this.transport.send(request, response);
            }
            catch ( SmbException se ) {
                log.debug("Send failed", se);
                if ( request instanceof SmbComTreeConnectAndX ) {
                    logoff(true);
                }
                request.digest = null;
                throw se;
            }
        }
    }


    void sessionSetup ( ServerMessageBlock andx, ServerMessageBlock andxResponse ) throws SmbException, GeneralSecurityException {
        synchronized ( transport() ) {

            while ( this.connectionState != 0 ) {
                if ( this.connectionState == 2 || this.connectionState == 3 ) // connected or disconnecting
                    return;
                try {
                    this.transport.wait();
                }
                catch ( InterruptedException ie ) {
                    throw new SmbException(ie.getMessage(), ie);
                }
            }
            this.connectionState = 1; // trying ...

            try {
                this.transport.connect();

                /*
                 * Session Setup And X Request / Response
                 */

                if ( log.isDebugEnabled() ) {
                    log.debug("sessionSetup: " + this.credentials);
                }

                /*
                 * We explicitly set uid to 0 here to prevent a new
                 * SMB_COM_SESSION_SETUP_ANDX from having it's uid set to an
                 * old value when the session is re-established. Otherwise a
                 * "The parameter is incorrect" error can occur.
                 */
                this.uid = 0;

                this.sessionSetup2(andx, andxResponse);
            }
            catch ( SmbException se ) {
                log.debug("Session setup failed", se);
                logoff(true);
                this.connectionState = 0;
                throw se;
            }
            finally {
                this.transport.notifyAll();
            }
        }

    }


    /**
     * @param andx
     * @param andxResponse
     */
    private void sessionSetup2 ( ServerMessageBlock andx, ServerMessageBlock andxResponse ) throws SmbException, GeneralSecurityException {
        SmbException ex = null;
        SmbComSessionSetupAndX request;
        SmbComSessionSetupAndXResponse response;
        SSPContext ctx = null;
        byte[] token = new byte[0];
        int state = 10;
        do {
            switch ( state ) {
            case 10: /* NTLM */
                if ( !this.credentials.isNull() && this.getTransport().hasCapability(SmbConstants.CAP_EXTENDED_SECURITY) ) {
                    log.debug("Extended security negotiated");
                    state = 20; /* NTLMSSP */
                    break;
                }

                log.debug("Performing legacy session setup");
                if ( ! ( this.credentials instanceof NtlmPasswordAuthentication ) ) {
                    throw new SmbAuthException("Incompatible credentials");
                }

                NtlmPasswordAuthentication npa = (NtlmPasswordAuthentication) this.credentials;

                request = new SmbComSessionSetupAndX(this, andx, this.getCredentials());
                response = new SmbComSessionSetupAndXResponse(this.getTransportContext().getConfig(), andxResponse);

                /*
                 * Create SMB signature digest if necessary
                 * Only the first SMB_COM_SESSION_SETUP_ANX with non-null or
                 * blank password initializes signing.
                 */
                if ( !npa.isNull() && this.getTransport().isSignatureSetupRequired() ) {
                    if ( npa.areHashesExternal() && this.getTransportContext().getConfig().getDefaultPassword() != null ) {
                        /*
                         * preauthentication
                         */
                        this.getTransport().getSmbSession(this.getTransportContext().withDefaultCredentials())
                                .getSmbTree(this.getTransportContext().getConfig().getLogonShare(), null).treeConnect(null, null);
                    }
                    else {
                        byte[] signingKey = npa.getSigningKey(this.getTransportContext(), this.getTransport().server.encryptionKey);
                        request.digest = new SigningDigest(signingKey, false);
                    }
                }

                try {
                    this.getTransport().send(request, response);
                }
                catch ( SmbAuthException sae ) {
                    throw sae;
                }
                catch ( SmbException se ) {
                    ex = se;
                }

                if ( response.isLoggedInAsGuest && this.getTransport().server.security != SmbConstants.SECURITY_SHARE
                        && !this.credentials.isAnonymous() ) {
                    throw new SmbAuthException(NtStatus.NT_STATUS_LOGON_FAILURE);
                }

                if ( ex != null )
                    throw ex;

                this.setUid(response.uid);

                if ( request.digest != null ) {
                    /* success - install the signing digest */
                    this.getTransport().digest = request.digest;
                }

                this.setSessionSetup(true);
                state = 0;

                break;
            case 20: /* NTLMSSP */
                Subject s = this.credentials.getSubject();
                final byte[] curToken = token;
                if ( ctx == null ) {
                    final boolean doSigning = ( this.getTransport().flags2 & SmbConstants.FLAGS2_SECURITY_SIGNATURES ) != 0;
                    String host = this.getTransport().address.getHostAddress();
                    try {
                        host = this.getTransport().address.getHostName();
                    }
                    catch ( Exception e ) {
                        log.debug("Failed to resolve host name", e);
                    }

                    if ( s == null ) {
                        ctx = this.credentials.createContext(this.getTransportContext(), host, this.transport.server.encryptionKey, doSigning);
                    }
                    else {
                        try {
                            final String hostName = host;
                            ctx = Subject.doAs(s, new PrivilegedExceptionAction<SSPContext>() {

                                @Override
                                public SSPContext run () throws Exception {
                                    return getCredentials()
                                            .createContext(getTransportContext(), hostName, getTransport().server.encryptionKey, doSigning);
                                }

                            });
                        }
                        catch ( PrivilegedActionException e ) {
                            if ( e.getException() instanceof SmbException ) {
                                throw (SmbException) e.getException();
                            }
                            throw new SmbException("Unexpected exception during context initialization", e);
                        }
                    }
                }

                final SSPContext curCtx = ctx;

                if ( log.isDebugEnabled() ) {
                    log.debug(ctx);
                }

                if ( ctx.isEstablished() ) {
                    this.setNetbiosName(ctx.getNetbiosName());
                    this.sessionKey = ctx.getSigningKey();
                    this.setSessionSetup(true);
                    state = 0;
                    break;
                }

                try {
                    if ( s != null ) {

                        try {
                            token = Subject.doAs(s, new PrivilegedExceptionAction<byte[]>() {

                                @Override
                                public byte[] run () throws Exception {
                                    return curCtx.initSecContext(curToken, 0, curToken == null ? 0 : curToken.length);
                                }

                            });
                        }
                        catch ( PrivilegedActionException e ) {
                            if ( e.getException() instanceof SmbException ) {
                                throw (SmbException) e.getException();
                            }
                            throw new SmbException("Unexpected exception during context initialization", e);
                        }
                    }
                    else {
                        token = ctx.initSecContext(token, 0, token == null ? 0 : token.length);
                    }
                }
                catch ( SmbException se ) {
                    /*
                     * We must close the transport or the server will be expecting a
                     * Type3Message. Otherwise, when we send a Type1Message it will return
                     * "Invalid parameter".
                     */
                    try {
                        this.getTransport().disconnect(true);
                    }
                    catch ( IOException ioe ) {
                        log.debug("Disconnect failed");
                    }
                    this.setUid(0);
                    throw se;
                }

                if ( token != null ) {
                    request = new SmbComSessionSetupAndX(this, null, token);
                    response = new SmbComSessionSetupAndXResponse(this.getTransportContext().getConfig(), null);

                    if ( !this.credentials.isNull() && ctx.isEstablished() && this.getTransport().isSignatureSetupRequired() ) {
                        byte[] signingKey = ctx.getSigningKey();
                        if ( signingKey != null )
                            request.digest = new SigningDigest(signingKey, true);

                        this.sessionKey = signingKey;
                    }

                    request.uid = this.getUid();
                    this.setUid(0);

                    try {
                        this.getTransport().send(request, response);
                    }
                    catch ( SmbAuthException sae ) {
                        throw sae;
                    }
                    catch ( SmbException se ) {
                        ex = se;
                        /*
                         * Apparently once a successfull NTLMSSP login occurs, the
                         * server will return "Access denied" even if a logoff is
                         * sent. Unfortunately calling disconnect() doesn't always
                         * actually shutdown the connection before other threads
                         * have committed themselves (e.g. InterruptTest example).
                         */
                        try {
                            this.getTransport().disconnect(true);
                        }
                        catch ( Exception e ) {
                            log.debug("Failed to disconnect transport", e);
                        }
                    }

                    if ( response.isLoggedInAsGuest && this.credentials.isGuest() == false ) {
                        throw new SmbAuthException(NtStatus.NT_STATUS_LOGON_FAILURE);
                    }

                    if ( ex != null )
                        throw ex;

                    this.setUid(response.uid);

                    if ( request.digest != null ) {
                        /* success - install the signing digest */
                        this.getTransport().digest = request.digest;
                    }

                    token = response.blob;
                }

                break;
            default:
                throw new SmbException("Unexpected session setup state: " + state);
            }
        }
        while ( state != 0 );
    }


    void logoff ( boolean inError ) {
        synchronized ( transport() ) {

            if ( this.connectionState != 2 ) // not-connected
                return;
            this.connectionState = 3; // disconnecting

            this.netbiosName = null;

            for ( SmbTree t : this.trees ) {
                t.treeDisconnect(inError);
            }

            if ( !inError && this.transport.server.security != SmbConstants.SECURITY_SHARE ) {
                /*
                 * Logoff And X Request / Response
                 */

                SmbComLogoffAndX request = new SmbComLogoffAndX(this.getConfig(), null);
                request.uid = this.uid;
                try {
                    this.transport.send(request, null);
                }
                catch ( SmbException se ) {
                    log.debug("SmbComLogoffAndX failed", se);
                }
                this.uid = 0;
            }

            this.connectionState = 0;
            this.transport.notifyAll();
        }
    }


    @Override
    public String toString () {
        return "SmbSession[credentials=" + this.transportContext.getCredentials() + ",uid=" + this.uid + ",connectionState=" + this.connectionState
                + "]";
    }


    void setUid ( int uid ) {
        this.uid = uid;
    }


    void setSessionSetup ( boolean b ) {
        if ( b ) {
            this.connectionState = 2;
        }
    }


    /**
     * @param netbiosName2
     */
    void setNetbiosName ( String netbiosName ) {
        this.netbiosName = netbiosName;
    }


    /**
     * @return
     */
    public CIFSContext getTransportContext () {
        return this.transport.getTransportContext();
    }


    /**
     * @return
     */
    public SmbTransport getTransport () {
        return this.transport;
    }


    /**
     * @return
     */
    public int getUid () {
        return this.uid;
    }


    /**
     * @return
     */
    public long getExpiration () {
        return this.expiration;
    }


    /**
     * @return
     */
    public SmbCredentials getCredentials () {
        return this.credentials;
    }

}
