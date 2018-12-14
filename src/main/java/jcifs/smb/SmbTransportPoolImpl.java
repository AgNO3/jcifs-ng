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
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.Address;
import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.SmbConstants;
import jcifs.SmbTransport;
import jcifs.SmbTransportPool;
import jcifs.util.transport.TransportException;


/**
 * @author mbechler
 * @internal
 */
public class SmbTransportPoolImpl implements SmbTransportPool {

    private static final Logger log = LoggerFactory.getLogger(SmbTransportPoolImpl.class);

    private final List<SmbTransportImpl> connections = new LinkedList<>();
    private final List<SmbTransportImpl> nonPooledConnections = new LinkedList<>();
    final Map<String, Integer> failCounts = new ConcurrentHashMap<>();


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
            if ( log.isTraceEnabled() ) {
                log.trace("Exclusive " + nonPooled + " enforced signing " + forceSigning);
            }
            if ( !nonPooled && tc.getConfig().getSessionLimit() != 1 ) {
                SmbTransportImpl existing = findConnection(tc, address, port, localAddr, localPort, hostName, forceSigning, false);
                if ( existing != null ) {
                    return existing;
                }
            }
            SmbTransportImpl conn = new SmbTransportImpl(tc, address, port, localAddr, localPort, forceSigning);
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
     * @param tc
     * @param address
     * @param port
     * @param localAddr
     * @param localPort
     * @param hostName
     * @param forceSigning
     * @return
     */
    private SmbTransportImpl findConnection ( CIFSContext tc, Address address, int port, InetAddress localAddr, int localPort, String hostName,
            boolean forceSigning, boolean connectedOnly ) {
        for ( SmbTransportImpl conn : this.connections ) {
            if ( conn.matches(address, port, localAddr, localPort, hostName)
                    && ( tc.getConfig().getSessionLimit() == 0 || conn.getNumSessions() < tc.getConfig().getSessionLimit() ) ) {
                try {
                    if ( connectedOnly && conn.isDisconnected() ) {
                        continue;
                    }

                    if ( forceSigning && !conn.isSigningEnforced() ) {
                        // if signing is enforced and was not on the connection, skip
                        if ( log.isTraceEnabled() ) {
                            log.debug("Cannot reuse, signing enforced but connection does not have it enabled " + conn);
                        }
                        continue;
                    }

                    if ( !forceSigning && !tc.getConfig().isSigningEnforced() && conn.isSigningEnforced()
                            && !conn.getNegotiateResponse().isSigningRequired() ) {
                        // if signing is not enforced, dont use connections that have signing enforced
                        // for purposes that dont require it.
                        if ( log.isTraceEnabled() ) {
                            log.debug("Cannot reuse, signing enforced on connection " + conn);
                        }
                        continue;
                    }

                    if ( !conn.getNegotiateResponse().canReuse(tc, forceSigning) ) {
                        if ( log.isTraceEnabled() ) {
                            log.trace("Cannot reuse, different config " + conn);
                        }
                        continue;
                    }
                }
                catch ( CIFSException e ) {
                    log.debug("Error while checking for reuse", e);
                    continue;
                }

                if ( log.isTraceEnabled() ) {
                    log.trace("Reusing transport connection " + conn);
                }
                return conn.acquire();
            }
        }

        return null;
    }


    @Override
    public SmbTransportImpl getSmbTransport ( CIFSContext tf, String name, int port, boolean exclusive, boolean forceSigning ) throws IOException {

        Address[] addrs = tf.getNameServiceClient().getAllByName(name, true);

        if ( addrs == null || addrs.length == 0 ) {
            throw new UnknownHostException(name);
        }

        Arrays.sort(addrs, new Comparator<Address>() {

            @Override
            public int compare ( Address o1, Address o2 ) {
                Integer fail1 = SmbTransportPoolImpl.this.failCounts.get(o1.getHostAddress());
                Integer fail2 = SmbTransportPoolImpl.this.failCounts.get(o2.getHostAddress());
                if ( fail1 == null ) {
                    fail1 = 0;
                }
                if ( fail2 == null ) {
                    fail2 = 0;
                }
                return Integer.compare(fail1, fail2);
            }

        });

        synchronized ( this.connections ) {
            for ( Address addr : addrs ) {
                SmbTransportImpl found = findConnection(
                    tf,
                    addr,
                    port,
                    tf.getConfig().getLocalAddr(),
                    tf.getConfig().getLocalPort(),
                    name,
                    forceSigning,
                    true);
                if ( found != null ) {
                    return found;
                }
            }
        }

        IOException ex = null;
        for ( Address addr : addrs ) {
            try ( SmbTransportImpl trans = getSmbTransport(tf, addr, port, exclusive, forceSigning).unwrap(SmbTransportImpl.class) ) {
                try {
                    trans.ensureConnected();
                }
                catch ( IOException e ) {
                    removeTransport(trans);
                    throw e;
                }
                return trans.acquire();
            }
            catch ( IOException e ) {
                String hostAddress = addr.getHostAddress();
                Integer failCount = this.failCounts.get(hostAddress);
                if ( failCount == null ) {
                    this.failCounts.put(hostAddress, 1);
                }
                else {
                    this.failCounts.put(hostAddress, failCount + 1);
                }
                ex = e;
            }
        }

        if ( ex != null ) {
            throw ex;
        }
        throw new TransportException("All connection attempts failed");
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
    public boolean close () throws CIFSException {
        boolean inUse = false;
        
        List<SmbTransportImpl> toClose;
        synchronized ( this.connections ) {
            log.debug("Closing pool");
            toClose = new LinkedList<>(this.connections);
            toClose.addAll(this.nonPooledConnections);
            this.connections.clear();
            this.nonPooledConnections.clear();
        }
        for ( SmbTransportImpl conn : toClose ) {
            try {
                inUse |= conn.disconnect(false, false);
            }
            catch ( IOException e ) {
                log.warn("Failed to close connection", e);
            }
        }
        return inUse;
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
        catch ( SmbException e ) {
            throw e;
        }
        catch ( IOException e ) {
            throw new SmbException("Connection failed", e);
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
              SmbSessionInternal smbSession = smbTransport.getSmbSession(tf, dc.getHostName(), null).unwrap(SmbSessionInternal.class);
              SmbTreeInternal tree = smbSession.getSmbTree(tf.getConfig().getLogonShare(), null).unwrap(SmbTreeInternal.class) ) {
            tree.connectLogon(tf);
        }
    }

}
