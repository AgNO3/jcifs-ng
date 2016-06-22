/*
 * © 2016 AgNO3 Gmbh & Co. KG
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
import java.util.LinkedList;
import java.util.List;

import org.apache.log4j.Logger;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.SmbTransportPool;
import jcifs.UniAddress;
import jcifs.netbios.NbtAddress;


/**
 * @author mbechler
 *
 */
public class SmbTransportPoolImpl implements SmbTransportPool {

    private static final Logger log = Logger.getLogger(SmbTransportPool.class);

    private final List<SmbTransport> connections = new LinkedList<>();
    private final List<SmbTransport> nonPooledConnections = new LinkedList<>();

    private NbtAddress[] dcList = null;
    private long dcListExpiration;
    private static int dcListCounter;


    @Override
    public SmbTransport getSmbTransport ( CIFSContext tc, UniAddress address, int port, boolean nonPooled ) {
        return getSmbTransport(tc, address, port, tc.getConfig().getLocalAddr(), tc.getConfig().getLocalPort(), null, nonPooled);
    }


    @Override
    public SmbTransport getSmbTransport ( CIFSContext tc, UniAddress address, int port, InetAddress localAddr, int localPort, String hostName,
            boolean nonPooled ) {
        synchronized ( this.connections ) {
            SmbComNegotiate negotiate = new SmbComNegotiate(tc.getConfig());
            if ( nonPooled || tc.getConfig().getSessionLimit() != 1 ) {
                for ( SmbTransport conn : this.connections ) {
                    if ( conn.matches(address, port, localAddr, localPort, hostName)
                            && ( tc.getConfig().getSessionLimit() == 0 || conn.sessions.size() < tc.getConfig().getSessionLimit() ) ) {
                        /*
                         * Compare the flags2 field in SMB block to decide
                         * // whether the authentication method is changed. Because one
                         * // tranport can only negotiate only once, if authentication
                         * // method is changed, we need to re-create the transport to
                         * re-negotiate with server.
                         */
                        if ( conn.getNegotiateRequest().flags2 == negotiate.flags2 ) {
                            if ( log.isDebugEnabled() ) {
                                log.debug("Reusing transport connection " + conn);
                            }
                            return conn;
                        }
                    }
                }
            }
            SmbTransport conn = new SmbTransport(tc, negotiate, address, port, localAddr, localPort);
            if ( log.isDebugEnabled() ) {
                log.debug("New transport connection " + conn);
            }
            if ( nonPooled ) {
                this.nonPooledConnections.add(conn);
            }
            else {
                this.connections.add(0, conn);
            }
            return conn;
        }
    }


    @Override
    public void removeTransport ( SmbTransport trans ) {
        synchronized ( this.connections ) {
            if ( log.isDebugEnabled() ) {
                log.debug("Removing transport connection " + trans + " (" + System.identityHashCode(trans) + ")");
            }
            this.connections.remove(trans);
            this.nonPooledConnections.remove(trans);
        }
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.SmbTransportPool#close()
     */
    @Override
    public void close () throws CIFSException {
        synchronized ( this.connections ) {
            List<SmbTransport> toClose = new LinkedList<>(this.connections);
            toClose.addAll(this.nonPooledConnections);
            for ( SmbTransport conn : toClose ) {
                try {
                    conn.disconnect(false);
                }
                catch ( IOException e ) {
                    log.warn("Failed to close connection", e);
                }
            }
            this.connections.clear();
            this.nonPooledConnections.clear();
        }
    }


    @Override
    public synchronized NtlmChallenge getChallengeForDomain ( CIFSContext tc, String domain ) throws SmbException, UnknownHostException {
        if ( domain == null ) {
            throw new SmbException("A domain was not specified");
        }
        long now = System.currentTimeMillis();
        int retry = 1;

        do {
            if ( this.dcListExpiration < now ) {
                NbtAddress[] list = NbtAddress.getAllByName(domain, 0x1C, null, null, tc);
                this.dcListExpiration = now + tc.getConfig().getNetbiosCacheTimeout() * 1000L;
                if ( list != null && list.length > 0 ) {
                    this.dcList = list;
                }
                else { /* keep using the old list */
                    this.dcListExpiration = now + 1000 * 60 * 15; /* 15 min */
                    log.warn("Failed to retrieve DC list from WINS");
                }
            }

            int max = Math.min(this.dcList.length, tc.getConfig().getNetbiosLookupRespLimit());
            for ( int j = 0; j < max; j++ ) {
                int i = dcListCounter++ % max;
                if ( this.dcList[ i ] != null ) {
                    try {
                        return interrogate(tc, this.dcList[ i ]);
                    }
                    catch ( SmbException se ) {
                        log.warn("Failed validate DC: " + this.dcList[ i ], se);
                    }
                    this.dcList[ i ] = null;
                }
            }

            /*
             * No DCs found, for retieval of list by expiring it and retry.
             */
            this.dcListExpiration = 0;
        }
        while ( retry-- > 0 );

        this.dcListExpiration = now + 1000 * 60 * 15; /* 15 min */
        throw new UnknownHostException("Failed to negotiate with a suitable domain controller for " + domain);
    }


    @Override
    public byte[] getChallenge ( UniAddress dc, CIFSContext tf ) throws SmbException {
        return getChallenge(dc, 0, tf);
    }


    public byte[] getChallenge ( UniAddress dc, int port, CIFSContext tf ) throws SmbException {
        SmbTransport trans = tf.getTransportPool().getSmbTransport(tf, dc, port, false);
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
    @Override
    public void logon ( UniAddress dc, CIFSContext tf ) throws SmbException {
        logon(dc, 0, tf);
    }


    public void logon ( UniAddress dc, int port, CIFSContext tf ) throws SmbException {
        SmbTransport smbTransport = tf.getTransportPool().getSmbTransport(tf, dc, port, false);
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


    private static NtlmChallenge interrogate ( CIFSContext tf, NbtAddress addr ) throws SmbException {
        UniAddress dc = new UniAddress(addr);
        SmbTransport trans = tf.getTransportPool().getSmbTransport(tf, dc, 0, false);
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

}
