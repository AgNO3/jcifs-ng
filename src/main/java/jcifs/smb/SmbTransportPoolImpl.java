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
import java.util.LinkedList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.Address;
import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.SmbConstants;
import jcifs.SmbTransport;
import jcifs.SmbTransportPool;


/**
 * @author mbechler
 * @internal
 */
public class SmbTransportPoolImpl implements SmbTransportPool {

    private static final Logger log = LoggerFactory.getLogger(SmbTransportPoolImpl.class);

    private final List<SmbTransportImpl> connections = new LinkedList<>();
    private final List<SmbTransportImpl> nonPooledConnections = new LinkedList<>();


    @Override
    public SmbTransportImpl getSmbTransport ( CIFSContext tc, Address address, int port, boolean nonPooled ) {
        return getSmbTransport(tc, address, port, tc.getConfig().getLocalAddr(), tc.getConfig().getLocalPort(), null, nonPooled);
    }


    @Override
    public SmbTransportImpl getSmbTransport ( CIFSContext tc, Address address, int port, boolean nonPooled, boolean forceSigning ) {
        return getSmbTransport(tc, address, port, tc.getConfig().getLocalAddr(), tc.getConfig().getLocalPort(), null, nonPooled, forceSigning);
    }


    @Override
    public SmbTransportImpl getSmbTransport ( CIFSContext tc, Address address, int port, InetAddress localAddr, int localPort, String hostName,
            boolean nonPooled ) {
        return getSmbTransport(tc, address, port, localAddr, localPort, hostName, nonPooled, false);
    }


    @Override
    public SmbTransportImpl getSmbTransport ( CIFSContext tc, Address address, int port, InetAddress localAddr, int localPort, String hostName,
            boolean nonPooled, boolean forceSigning ) {
        if ( port <= 0 ) {
            port = SmbConstants.DEFAULT_PORT;
        }
        synchronized ( this.connections ) {
            SmbComNegotiate negotiate = new SmbComNegotiate(tc.getConfig());
            if ( log.isTraceEnabled() ) {
                log.trace("Exclusive " + nonPooled + " enforced signing " + forceSigning);
            }
            if ( !nonPooled && tc.getConfig().getSessionLimit() != 1 ) {
                for ( SmbTransportImpl conn : this.connections ) {
                    if ( conn.matches(address, port, localAddr, localPort, hostName)
                            && ( tc.getConfig().getSessionLimit() == 0 || conn.sessions.size() < tc.getConfig().getSessionLimit() ) ) {

                        if ( forceSigning && !conn.signingEnforced ) {
                            // if signing is enforced and was not on the connection, skip
                            continue;
                        }

                        if ( !forceSigning && !tc.getConfig().isSigningEnforced() && conn.signingEnforced ) {
                            // if signing is not enforced, dont use connections that have signing enforced
                            // for purposes that dont require it.
                            continue;
                        }

                        /*
                         * Compare the flags2 field in SMB block to decide
                         * whether the authentication method is changed. Because one
                         * tranport can only negotiate only once, if authentication
                         * method is changed, we need to re-create the transport to
                         * re-negotiate with server.
                         */
                        if ( conn.getNegotiateRequest().flags2 != negotiate.flags2 ) {
                            continue;
                        }

                        if ( log.isTraceEnabled() ) {
                            log.trace("Reusing transport connection " + conn);
                        }
                        return conn.acquire();
                    }
                }
            }
            SmbTransportImpl conn = new SmbTransportImpl(tc, negotiate, address, port, localAddr, localPort, forceSigning);
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


    /**
     * 
     * @param trans
     * @return whether (non-exclusive) connection is in the pool
     */
    public boolean contains ( SmbTransport trans ) {
        synchronized ( this.connections ) {
            return this.connections.contains(trans);
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
            log.debug("Closing pool");
            List<SmbTransportImpl> toClose = new LinkedList<>(this.connections);
            toClose.addAll(this.nonPooledConnections);
            for ( SmbTransportImpl conn : toClose ) {
                try {
                    conn.disconnect(false, false);
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
    public byte[] getChallenge ( CIFSContext tf, Address dc ) throws SmbException {
        return getChallenge(tf, dc, 0);
    }


    @Override
    public byte[] getChallenge ( CIFSContext tf, Address dc, int port ) throws SmbException {
        try ( SmbTransportInternal trans = tf.getTransportPool()
                .getSmbTransport(tf, dc, port, false, !tf.getCredentials().isAnonymous() && tf.getConfig().isIpcSigningEnforced())
                .unwrap(SmbTransportInternal.class) ) {
            trans.ensureConnected();
            return trans.getServerEncryptionKey();
        }
    }


    @Override
    public void logon ( CIFSContext tf, Address dc ) throws SmbException {
        logon(tf, dc, 0);
    }


    @Override
    public void logon ( CIFSContext tf, Address dc, int port ) throws SmbException {
        try ( SmbTransportInternal smbTransport = tf.getTransportPool().getSmbTransport(tf, dc, port, false, tf.getConfig().isIpcSigningEnforced())
                .unwrap(SmbTransportInternal.class);
              SmbSessionInternal smbSession = smbTransport.getSmbSession(tf).unwrap(SmbSessionInternal.class);
              SmbTreeInternal tree = smbSession.getSmbTree(tf.getConfig().getLogonShare(), null).unwrap(SmbTreeInternal.class) ) {
            tree.connectLogon(tf);
        }
    }

}
