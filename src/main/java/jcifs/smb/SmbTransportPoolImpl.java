/**
 * © 2016 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 17.01.2016 by mbechler
 */
package jcifs.smb;


import java.io.IOException;
import java.net.InetAddress;
import java.util.LinkedList;
import java.util.List;

import org.apache.log4j.Logger;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.SmbTransportPool;
import jcifs.UniAddress;


/**
 * @author mbechler
 *
 */
public class SmbTransportPoolImpl implements SmbTransportPool {

    private static final Logger log = Logger.getLogger(SmbTransportPool.class);

    private final List<SmbTransport> connections = new LinkedList<>();


    @Override
    public SmbTransport getSmbTransport ( CIFSContext tc, UniAddress address, int port ) {
        return getSmbTransport(tc, address, port, tc.getConfig().getLocalAddr(), tc.getConfig().getLocalPort(), null);
    }


    @Override
    public SmbTransport getSmbTransport ( CIFSContext tc, UniAddress address, int port, InetAddress localAddr, int localPort, String hostName ) {
        synchronized ( this.connections ) {
            SmbComNegotiate negotiate = new SmbComNegotiate(tc.getConfig());
            if ( tc.getConfig().getSessionLimit() != 1 ) {
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
            this.connections.add(0, conn);
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
            for ( SmbTransport conn : toClose ) {
                try {
                    conn.disconnect(false);
                }
                catch ( IOException e ) {
                    log.warn("Failed to close connection", e);
                }
            }
        }
    }
}
