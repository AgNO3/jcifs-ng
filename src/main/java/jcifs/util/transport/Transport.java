/*
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
package jcifs.util.transport;


import java.io.IOException;
import java.io.InputStream;
import java.net.SocketTimeoutException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.RuntimeCIFSException;


/**
 * This class simplifies communication for protocols that support
 * multiplexing requests. It encapsulates a stream and some protocol
 * knowledge (provided by a concrete subclass) so that connecting,
 * disconnecting, sending, and receiving can be syncronized
 * properly. Apparatus is provided to send and receive requests
 * concurrently.
 */

public abstract class Transport implements Runnable, AutoCloseable {

    private static int id = 0;
    private static final Logger log = LoggerFactory.getLogger(Transport.class);


    /**
     * Read bytes from the input stream into a buffer
     * 
     * @param in
     * @param b
     * @param off
     * @param len
     * @return number of bytes read
     * @throws IOException
     */
    public static int readn ( InputStream in, byte[] b, int off, int len ) throws IOException {
        int i = 0, n = -5;

        if ( off + len > b.length ) {
            throw new IOException("Buffer too short, bufsize " + b.length + " read " + len);
        }

        while ( i < len ) {
            n = in.read(b, off + i, len - i);
            if ( n <= 0 ) {
                break;
            }
            i += n;
        }

        return i;
    }

    /*
     * state values
     * 0 - not connected
     * 1 - connecting
     * 2 - run connected
     * 3 - connected
     * 4 - error
     * 5 - disconnecting
     */
    protected volatile int state = 0;

    protected String name = "Transport" + id++;
    volatile Thread thread;
    volatile TransportException te;

    protected Map<Request, Response> response_map = new ConcurrentHashMap<>(4);
    private final AtomicLong usageCount = new AtomicLong(1);


    /**
     * @return session increased usage count
     */
    public Transport acquire () {
        long usage = this.usageCount.incrementAndGet();
        if ( log.isTraceEnabled() ) {
            log.trace("Acquire transport " + usage + " " + this);
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
        release();
    }


    /**
     * 
     */
    public void release () {
        long usage = this.usageCount.decrementAndGet();
        if ( log.isTraceEnabled() ) {
            log.trace("Release transport " + usage + " " + this);
        }

        if ( usage == 0 ) {
            if ( log.isDebugEnabled() ) {
                log.debug("Transport usage dropped to zero " + this);
            }
        }
        else if ( usage < 0 ) {
            throw new RuntimeCIFSException("Usage count dropped below zero");
        }
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#finalize()
     */
    @Override
    protected void finalize () throws Throwable {
        if ( !isDisconnected() && this.usageCount.get() != 0 ) {
            log.warn("Session was not properly released");
        }
    }


    /**
     * @return the number of known usages
     */
    protected long getUsageCount () {
        return this.usageCount.get();
    }


    protected abstract void makeKey ( Request request ) throws IOException;


    protected abstract Request peekKey () throws IOException;


    protected abstract void doSend ( Request request ) throws IOException;


    protected abstract void doRecv ( Response response ) throws IOException;


    protected abstract void doSkip () throws IOException;


    /**
     * 
     * @return whether the transport is disconnected
     */
    public boolean isDisconnected () {
        return this.state == 4 || this.state == 5 || this.state == 0;
    }


    /**
     * Send a request message and recieve response
     * 
     * @param request
     * @param response
     * @param timeout
     * @throws IOException
     */
    public synchronized void sendrecv ( Request request, Response response, long timeout ) throws IOException {
        makeKey(request);
        response.isReceived = false;
        response.isError = false;
        try {
            if ( timeout > 0 ) {
                response.expiration = System.currentTimeMillis() + timeout;
            }
            else {
                response.expiration = null;
            }
            this.response_map.put(request, response);
            doSend(request);
            while ( !response.isReceived ) {
                if ( timeout > 0 ) {
                    wait(timeout);
                    timeout = response.expiration - System.currentTimeMillis();
                    if ( response.isError ) {
                        throw new TransportException(this.name + " error reading response to " + request, response.exception);
                    }
                    if ( isDisconnected() ) {
                        throw new TransportException("Transport was disconnected while waiting for a response");
                    }
                    if ( timeout <= 0 ) {
                        if ( log.isDebugEnabled() ) {
                            log.debug("State is " + this.state);
                        }
                        throw new TransportException(this.name + " timedout waiting for response to " + request);
                    }
                }
                else {
                    wait();
                    if ( log.isDebugEnabled() ) {
                        log.debug("Wait returned state is " + this.state);
                    }
                    if ( isDisconnected() ) {
                        throw new InterruptedException("Transport was disconnected while waiting for a response");
                    }
                }
            }
        }
        catch ( IOException ioe ) {
            log.debug("sendrecv failed", ioe);
            try {
                disconnect(true);
            }
            catch ( IOException ioe2 ) {
                ioe.addSuppressed(ioe2);
                log.info("disconnect failed", ioe2);
            }
            throw ioe;
        }
        catch ( InterruptedException ie ) {
            throw new TransportException(ie);
        }
        finally {
            this.response_map.remove(request);
        }
    }


    private void loop () {
        while ( this.thread == Thread.currentThread() ) {
            try {
                Request key;
                try {
                    key = peekKey();
                }
                catch ( SocketTimeoutException e ) {
                    log.trace("Socket timeout during peekKey", e);
                    if ( getUsageCount() > 0 ) {
                        if ( log.isDebugEnabled() ) {
                            log.debug("Transport still in use, no idle timeout " + this);
                        }
                        // notify, so that callers with timed-out requests can handle them
                        synchronized ( this ) {
                            notifyAll();
                        }
                        continue;
                    }

                    if ( log.isDebugEnabled() ) {
                        log.debug(String.format("Idle timeout on %s", this.name));
                    }
                    throw e;
                }
                if ( key == null ) {
                    synchronized ( this ) {
                        for ( Response response : this.response_map.values() ) {
                            response.isError = true;
                        }
                    }
                    throw new IOException("end of stream");
                }
                synchronized ( this ) {
                    Response response = this.response_map.get(key);
                    if ( response == null ) {
                        if ( log.isTraceEnabled() ) {
                            log.trace("Invalid key, skipping message");
                        }
                        doSkip();
                    }
                    else {
                        doRecv(response);
                        response.isReceived = true;
                        notifyAll();
                    }
                }
            }
            catch ( Exception ex ) {
                String msg = ex.getMessage();
                boolean timeout = ( ex instanceof SocketTimeoutException ) || msg != null && msg.equals("Read timed out");
                boolean closed = msg != null && msg.equals("Socket closed");

                if ( closed ) {
                    log.trace("Remote closed connection");
                }
                else if ( !timeout ) {
                    log.debug("recv failed", ex);
                }

                synchronized ( this ) {
                    try {
                        disconnect(!timeout, false);
                    }
                    catch ( IOException ioe ) {
                        ex.addSuppressed(ioe);
                        log.warn("Failed to disconnect", ioe);
                    }
                    log.debug("Disconnected");

                    notifyAll();
                    log.debug("Notified clients");
                }
            }
        }

    }


    /*
     * Build a connection. Only one thread will ever call this method at
     * any one time. If this method throws an exception or the connect timeout
     * expires an encapsulating TransportException will be thrown from connect
     * and the transport will be in error.
     */

    protected abstract void doConnect () throws Exception;


    /*
     * Tear down a connection. If the hard parameter is true, the diconnection
     * procedure should not initiate or wait for any outstanding requests on
     * this transport.
     */

    protected abstract void doDisconnect ( boolean hard, boolean inUse ) throws IOException;


    /**
     * Connect the transport
     * 
     * @param timeout
     * @throws TransportException
     */
    public synchronized void connect ( long timeout ) throws TransportException {
        try {
            switch ( this.state ) {
            case 0:
                break;
            case 3:
                return; // already connected
            case 4:
                this.state = 0;
                throw new TransportException("Connection in error", this.te);
            case 5:
                log.debug("Trying to connect a disconnected transport");
                return;
            default:
                TransportException tex = new TransportException("Invalid state: " + this.state);
                this.state = 0;
                throw tex;
            }

            if ( log.isDebugEnabled() ) {
                log.debug("Connecting " + this.name);
            }

            this.state = 1;
            this.te = null;

            Thread t = new Thread(this, this.name);
            t.setDaemon(true);
            this.thread = t;

            synchronized ( this.thread ) {
                t.start();
                t.wait(timeout); /* wait for doConnect */

                switch ( this.state ) {
                case 1: /* doConnect never returned */
                    this.state = 0;
                    cleanupThread();
                    throw new ConnectionTimeoutException("Connection timeout");
                case 2:
                    if ( this.te != null ) { /* doConnect throw Exception */
                        this.state = 4; /* error */
                        cleanupThread();
                        throw this.te;
                    }
                    this.state = 3; /* Success! */
                    return;
                }
            }
        }
        catch ( InterruptedException ie ) {
            this.state = 0;
            cleanupThread();
            throw new TransportException(ie);
        }
        finally {
            /*
             * This guarantees that we leave in a valid state
             */
            if ( this.state != 0 && this.state != 3 && this.state != 4 && this.state != 5 ) {
                log.error("Invalid state: " + this.state);
                this.state = 0;
                cleanupThread();
            }
        }
    }


    /**
     * @throws TransportException
     * 
     */
    private synchronized void cleanupThread () throws TransportException {
        Thread t = this.thread;
        if ( t != null && Thread.currentThread() != t ) {
            this.thread = null;
            try {
                log.debug("Interrupting transport thread");
                t.interrupt();
                log.debug("Joining transport thread");
                t.join();
                log.debug("Joined transport thread");
            }
            catch ( InterruptedException e ) {
                throw new TransportException("Failed to join transport thread", e);
            }
        }
        else if ( t != null ) {
            this.thread = null;
        }
    }


    /**
     * Disconnect the transport
     * 
     * @param hard
     * @throws IOException
     */
    public synchronized void disconnect ( boolean hard ) throws IOException {
        disconnect(hard, true);
    }


    /**
     * Disconnect the transport
     * 
     * @param hard
     * @param inUse
     *            whether the caller is holding a usage reference on the transport
     * @throws IOException
     */
    public synchronized void disconnect ( boolean hard, boolean inUse ) throws IOException {
        IOException ioe = null;

        switch ( this.state ) {
        case 0: /* not connected - just return */
        case 5:
            return;
        case 2:
            hard = true;
        case 3: /* connected - go ahead and disconnect */
            if ( this.response_map.size() != 0 && !hard ) {
                break; /* outstanding requests */
            }
            try {
                this.state = 5;
                doDisconnect(hard, inUse);
                this.state = 0;
            }
            catch ( IOException ioe0 ) {
                this.state = 0;
                ioe = ioe0;
            }
        case 4: /* failed to connect - reset the transport */
            // thread is cleaned up by connect routine, joining it here causes a deadlock
            this.thread = null;
            this.state = 0;
            break;
        default:
            log.error("Invalid state: " + this.state);
            this.thread = null;
            this.state = 0;
            break;
        }

        if ( ioe != null )
            throw ioe;
    }


    @Override
    public void run () {
        Thread run_thread = Thread.currentThread();
        Exception ex0 = null;

        try {
            /*
             * We cannot synchronize (run_thread) here or the caller's
             * thread.wait( timeout ) cannot reaquire the lock and
             * return which would render the timeout effectively useless.
             */
            if ( this.state != 5 ) {
                doConnect();
            }
        }
        catch ( Exception ex ) {
            ex0 = ex; // Defer to below where we're locked
            return;
        }
        finally {
            synchronized ( run_thread ) {
                if ( run_thread != this.thread ) {
                    /*
                     * Thread no longer the one setup for this transport --
                     * doConnect returned too late, just ignore.
                     */
                    if ( ex0 instanceof SocketTimeoutException ) {
                        log.debug("Timeout connecting", ex0);
                    }
                    else if ( ex0 != null ) {
                        log.warn("Exception in transport thread", ex0); //$NON-NLS-1$
                    }
                    return;
                }
                if ( ex0 != null ) {
                    this.te = new TransportException(ex0);
                }
                this.state = 2; // run connected
                run_thread.notify();
            }
        }

        /*
         * Proccess responses
         */
        loop();
    }


    @Override
    public String toString () {
        return this.name;
    }
}
