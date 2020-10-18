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
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.RuntimeCIFSException;
import jcifs.smb.RequestParam;


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
     * 6 - disconnected/invalid
     */
    protected volatile int state = 0;

    protected String name = "Transport" + id++;
    private volatile Thread thread;
    private volatile TransportException te;

    protected final Object inLock = new Object();
    protected final Object outLock = new Object();

    protected final Map<Long, Response> response_map = new ConcurrentHashMap<>(10);
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
            if ( log.isTraceEnabled() ) {
                log.trace("Transport usage dropped to zero " + this);
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


    protected abstract long makeKey ( Request request ) throws IOException;


    protected abstract Long peekKey () throws IOException;


    protected abstract void doSend ( Request request ) throws IOException;


    protected abstract void doRecv ( Response response ) throws IOException;


    protected abstract void doSkip ( Long key ) throws IOException;


    /**
     * 
     * @return whether the transport is disconnected
     */
    public boolean isDisconnected () {
        return this.state == 4 || this.state == 5 || this.state == 6 || this.state == 0;
    }


    /**
     * @return whether the transport is marked failed
     */
    public boolean isFailed () {
        return this.state == 5 || this.state == 6;
    }


    /**
     * Send a request message and recieve response
     * 
     * @param request
     * @param response
     * @param params
     * @return the response
     * @throws IOException
     */
    public <T extends Response> T sendrecv ( Request request, T response, Set<RequestParam> params ) throws IOException {
        if ( isDisconnected() && this.state != 5 ) {
            throw new TransportException("Transport is disconnected " + this.name);
        }
        try {
            long timeout = !params.contains(RequestParam.NO_TIMEOUT) ? getResponseTimeout(request) : 0;

            long firstKey = doSend(request, response, params, timeout);

            if ( Thread.currentThread() == this.thread ) {
                // we are in the transport thread, ie. on idle disconnecting
                // this is synchronous operation
                // This does not handle compound requests
                synchronized ( this.inLock ) {
                    Long peekKey = peekKey();
                    if ( peekKey == firstKey ) {
                        doRecv(response);
                        response.received();
                        return response;
                    }
                    doSkip(peekKey);
                }
            }

            return waitForResponses(request, response, timeout);
        }
        catch ( IOException ioe ) {
            log.warn("sendrecv failed", ioe);
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
            Response curResp = response;
            Request curReq = request;
            while ( curResp != null ) {
                this.response_map.remove(curResp.getMid());
                Request next = curReq.getNext();
                if ( next != null ) {
                    curReq = next;
                    curResp = next.getResponse();
                }
                else {
                    break;
                }
            }
        }
    }


    /**
     * @param request
     * @param response
     * @param params
     * @param timeout
     * @return
     * @throws IOException
     */
    protected <T extends Response> long doSend ( Request request, T response, Set<RequestParam> params, long timeout ) throws IOException {
        long firstKey = prepareRequests(request, response, params, timeout);
        doSend(request);
        return firstKey;
    }


    /**
     * @param request
     * @param response
     * @param params
     * @param timeout
     * @param firstKey
     * @return
     * @throws IOException
     */
    private <T extends Response> long prepareRequests ( Request request, T response, Set<RequestParam> params, long timeout ) throws IOException {
        Response curResp = response;
        Request curReq = request;
        long firstKey = 0;
        while ( curResp != null ) {
            curResp.reset();

            if ( params.contains(RequestParam.RETAIN_PAYLOAD) ) {
                curResp.retainPayload();
            }

            long k = makeKey(curReq);

            if ( firstKey == 0 ) {
                firstKey = k;
            }

            if ( timeout > 0 ) {
                curResp.setExpiration(System.currentTimeMillis() + timeout);
            }
            else {
                curResp.setExpiration(null);
            }

            curResp.setMid(k);
            this.response_map.put(k, curResp);

            Request next = curReq.getNext();
            if ( next != null ) {
                curReq = next;
                curResp = next.getResponse();
            }
            else {
                break;
            }
        }
        return firstKey;
    }


    /**
     * @param request
     * @param response
     * @param timeout
     * @return first response
     * @throws InterruptedException
     * @throws TransportException
     */
    private <T extends Response> T waitForResponses ( Request request, T response, long timeout ) throws InterruptedException, TransportException {
        Response curResp = response;
        Request curReq = request;
        while ( curResp != null ) {
            synchronized ( curResp ) {
                if ( !curResp.isReceived() ) {
                    if ( timeout > 0 ) {
                        curResp.wait(timeout);
                        if ( !curResp.isReceived() && handleIntermediate(curReq, curResp) ) {
                            continue;
                        }

                        if ( curResp.isError() ) {
                            throw new TransportException(this.name + " error reading response to " + curReq, curResp.getException());
                        }
                        if ( isDisconnected() && this.state != 5 ) {
                            throw new TransportException(
                                String.format(
                                    "Transport was disconnected while waiting for a response (transport: %s state: %d),",
                                    this.name,
                                    this.state));
                        }
                        timeout = curResp.getExpiration() - System.currentTimeMillis();
                        if ( timeout <= 0 ) {
                            if ( log.isDebugEnabled() ) {
                                log.debug("State is " + this.state);
                            }
                            throw new RequestTimeoutException(this.name + " timedout waiting for response to " + curReq);
                        }
                        continue;
                    }

                    curResp.wait();
                    if ( handleIntermediate(request, curResp) ) {
                        continue;
                    }
                    if ( log.isDebugEnabled() ) {
                        log.debug("Wait returned state is " + this.state);
                    }
                    if ( isDisconnected() ) {
                        throw new InterruptedException("Transport was disconnected while waiting for a response");
                    }
                    continue;
                }
            }

            Request next = curReq.getNext();
            if ( next != null ) {
                curReq = next;
                curResp = next.getResponse();
            }
            else {
                break;
            }
        }
        return response;
    }


    /**
     * @param request
     * @param response
     * @return
     */
    protected <T extends Response> boolean handleIntermediate ( Request request, T response ) {
        return false;
    }


    /**
     * @param request
     * @return
     */
    protected abstract int getResponseTimeout ( Request request );


    private void loop () {
        while ( this.thread == Thread.currentThread() ) {
            try {
                synchronized ( this.inLock ) {
                    Long key;
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
                            for ( Response response : this.response_map.values() ) {
                                synchronized ( response ) {
                                    response.notifyAll();
                                }
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
                                response.error();
                            }
                        }
                        throw new IOException("end of stream");
                    }

                    Response response = this.response_map.get(key);
                    if ( response == null ) {
                        if ( log.isDebugEnabled() ) {
                            log.debug("Unexpected message id, skipping message " + key);
                        }
                        doSkip(key);
                    }
                    else {
                        doRecv(response);
                        response.received();
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
                else if ( timeout ) {
                    log.warn("socket timeout in non peek state", ex);
                }
                else {
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

                    boolean notified = false;
                    Iterator<Entry<Long, Response>> iterator = this.response_map.entrySet().iterator();
                    while ( iterator.hasNext() ) {
                        Response resp = iterator.next().getValue();
                        resp.exception(ex);
                        iterator.remove();
                        notified = true;

                    }
                    if ( notified ) {
                        log.debug("Notified clients");
                    }
                    else {
                        log.warn("Exception without a request pending", ex);
                    }
                    return;
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

    protected abstract boolean doDisconnect ( boolean hard, boolean inUse ) throws IOException;


    /**
     * Connect the transport
     * 
     * @param timeout
     * @return whether the transport was connected
     * @throws TransportException
     */
    public synchronized boolean connect ( long timeout ) throws TransportException {
        int st = this.state;
        try {
            switch ( st ) {
            case 0:
                break;
            case 1:
                // already connecting
                this.thread.wait(timeout); /* wait for doConnect */
                st = this.state;
                switch ( st ) {
                case 1: /* doConnect never returned */
                    this.state = 6;
                    cleanupThread(timeout);
                    throw new ConnectionTimeoutException("Connection timeout");
                case 2:
                    if ( this.te != null ) { /* doConnect throw Exception */
                        this.state = 4; /* error */
                        cleanupThread(timeout);
                        throw this.te;
                    }
                    this.state = 3; /* Success! */
                    return true;
                }
                break;
            case 3:
                return true; // already connected
            case 4:
                this.state = 6;
                throw new TransportException("Connection in error", this.te);
            case 5:
            case 6:
                log.debug("Trying to connect a disconnected transport");
                return false;
            default:
                TransportException tex = new TransportException("Invalid state: " + st);
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

                st = this.state;
                switch ( st ) {
                case 1: /* doConnect never returned */
                    this.state = 6;
                    throw new ConnectionTimeoutException("Connection timeout");
                case 2:
                    if ( this.te != null ) { /* doConnect throw Exception */
                        this.state = 4; /* error */
                        throw this.te;
                    }
                    this.state = 3; /* Success! */
                    return true;
                case 3:
                    return true;
                default:
                    return false;
                }
            }
        }
        catch ( ConnectionTimeoutException e ) {
            cleanupThread(timeout);
            // allow to retry the connection
            this.state = 0;
            throw e;
        }
        catch ( InterruptedException ie ) {
            this.state = 6;
            cleanupThread(timeout);
            throw new TransportException(ie);
        }
        catch ( TransportException e ) {
            cleanupThread(timeout);
            throw e;
        }
        finally {
            /*
             * This guarantees that we leave in a valid state
             */
            st = this.state;
            if ( st != 0 && st != 3 && st != 4 && st != 5 && st != 6 ) {
                log.error("Invalid state: " + st);
                this.state = 6;
                cleanupThread(timeout);
            }
        }
    }


    /**
     * @param timeout
     * @throws TransportException
     * 
     */
    private synchronized void cleanupThread ( long timeout ) throws TransportException {
        Thread t = this.thread;
        if ( t != null && Thread.currentThread() != t ) {
            this.thread = null;
            try {
                log.debug("Interrupting transport thread");
                t.interrupt();
                log.debug("Joining transport thread");
                t.join(timeout);
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
     * @return whether conenction was in use
     * @throws IOException
     */
    public synchronized boolean disconnect ( boolean hard ) throws IOException {
        return disconnect(hard, true);
    }


    /**
     * Disconnect the transport
     * 
     * @param hard
     * @param inUse
     *            whether the caller is holding a usage reference on the transport
     * @return whether conenction was in use
     * @throws IOException
     */
    public synchronized boolean disconnect ( boolean hard, boolean inUse ) throws IOException {
        IOException ioe = null;

        switch ( this.state ) {
        case 0: /* not connected - just return */
        case 5:
        case 6:
            return false;
        case 2:
            hard = true;
        case 3: /* connected - go ahead and disconnect */
            if ( this.response_map.size() != 0 && !hard && inUse ) {
                break; /* outstanding requests */
            }
            try {
                this.state = 5;
                boolean wasInUse = doDisconnect(hard, inUse);
                this.state = 6;
                return wasInUse;
            }
            catch ( IOException ioe0 ) {
                this.state = 6;
                ioe = ioe0;
            }
        case 4: /* failed to connect - reset the transport */
            // thread is cleaned up by connect routine, joining it here causes a deadlock
            this.thread = null;
            this.state = 6;
            break;
        default:
            log.error("Invalid state: " + this.state);
            this.thread = null;
            this.state = 6;
            break;
        }

        if ( ioe != null )
            throw ioe;

        return false;
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
            if ( this.state != 5 && this.state != 6 ) {
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

                if ( ex0 instanceof SocketTimeoutException ) {
                    this.te = new ConnectionTimeoutException(ex0);
                }
                else if ( ex0 != null ) {
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
