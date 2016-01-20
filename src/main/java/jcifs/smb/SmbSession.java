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


import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.apache.log4j.Logger;

import jcifs.CIFSContext;
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

                this.credentials.sessionSetup(this, andx, andxResponse);
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
