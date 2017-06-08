/* jcifs msrpc client library in Java
 * Copyright (C) 2006  "Michael B. Allen" <jcifs at samba dot org>
 *                   "Eric Glass" <jcifs at samba dot org>
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

package jcifs.dcerpc;


import java.io.IOException;
import java.net.MalformedURLException;
import java.util.concurrent.atomic.AtomicInteger;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.dcerpc.ndr.NdrBuffer;
import jcifs.dcerpc.ndr.NdrException;


/**
 * 
 * 
 */
public abstract class DcerpcHandle implements DcerpcConstants, AutoCloseable {

    /*
     * Bindings are in the form:
     * proto:\\server[key1=val1,key2=val2]
     * or
     * proto:server[key1=val1,key2=val2]
     * or
     * proto:[key1=val1,key2=val2]
     *
     * If a key is absent it is assumed to be 'endpoint'. Thus the
     * following are equivalent:
     * proto:\\ts0.win.net[endpoint=\pipe\srvsvc]
     * proto:ts0.win.net[\pipe\srvsvc]
     *
     * If the server is absent it is set to "127.0.0.1"
     */
    protected static DcerpcBinding parseBinding ( String str ) throws DcerpcException {
        int state, mark, si;
        char[] arr = str.toCharArray();
        String proto = null, key = null;
        DcerpcBinding binding = null;

        state = mark = si = 0;
        do {
            char ch = arr[ si ];

            switch ( state ) {
            case 0:
                if ( ch == ':' ) {
                    proto = str.substring(mark, si);
                    mark = si + 1;
                    state = 1;
                }
                break;
            case 1:
                if ( ch == '\\' ) {
                    mark = si + 1;
                    break;
                }
                state = 2;
            case 2:
                if ( ch == '[' ) {
                    String server = str.substring(mark, si).trim();
                    if ( server.length() == 0 )
                        server = "127.0.0.1";
                    binding = new DcerpcBinding(proto, str.substring(mark, si));
                    mark = si + 1;
                    state = 5;
                }
                break;
            case 5:
                if ( ch == '=' ) {
                    key = str.substring(mark, si).trim();
                    mark = si + 1;
                }
                else if ( ch == ',' || ch == ']' ) {
                    String val = str.substring(mark, si).trim();
                    if ( key == null )
                        key = "endpoint";
                    if ( binding != null ) {
                        binding.setOption(key, val);
                    }
                    key = null;
                }
                break;
            default:
                si = arr.length;
            }

            si++;
        }
        while ( si < arr.length );

        if ( binding == null || binding.getEndpoint() == null )
            throw new DcerpcException("Invalid binding URL: " + str);

        return binding;
    }

    private static final AtomicInteger call_id = new AtomicInteger(1);

    private final DcerpcBinding binding;
    private int max_xmit = 4280;
    private int max_recv = this.max_xmit;
    private int state = 0;
    private DcerpcSecurityProvider securityProvider = null;
    private CIFSContext transportContext;


    /**
     * @param tc
     * 
     */
    public DcerpcHandle ( CIFSContext tc ) {
        this.transportContext = tc;
        this.binding = null;
    }


    /**
     * @param tc
     * @param binding
     */
    public DcerpcHandle ( CIFSContext tc, DcerpcBinding binding ) {
        this.transportContext = tc;
        this.binding = binding;
    }


    /**
     * @return the binding
     */
    DcerpcBinding getBinding () {
        return this.binding;
    }


    /**
     * @return the max_recv
     */
    int getMaxRecv () {
        return this.max_recv;
    }


    /**
     * @return the max_xmit
     */
    int getMaxXmit () {
        return this.max_xmit;
    }


    /**
     * Get a handle to a service
     * 
     * @param url
     * @param tc
     *            context to use
     * @return a DCERPC handle for the given url
     * @throws MalformedURLException
     * @throws DcerpcException
     */
    public static DcerpcHandle getHandle ( String url, CIFSContext tc ) throws MalformedURLException, DcerpcException {
        return getHandle(url, tc, false);
    }


    /**
     * Get a handle to a service
     * 
     * @param url
     * @param tc
     * @param unshared
     *            whether an exclusive connection should be used
     * @return a DCERPC handle for the given url
     * @throws MalformedURLException
     * @throws DcerpcException
     */
    public static DcerpcHandle getHandle ( String url, CIFSContext tc, boolean unshared ) throws MalformedURLException, DcerpcException {
        if ( url.startsWith("ncacn_np:") ) {
            return new DcerpcPipeHandle(url, tc, unshared);
        }
        throw new DcerpcException("DCERPC transport not supported: " + url);
    }


    /**
     * Bind the handle
     * 
     * @throws DcerpcException
     * @throws IOException
     */
    public void bind () throws DcerpcException, IOException {
        synchronized ( this ) {
            try {
                this.state = 1;
                DcerpcMessage bind = new DcerpcBind(this.binding, this);
                sendrecv(bind);
            }
            catch ( IOException ioe ) {
                this.state = 0;
                throw ioe;
            }
        }
    }


    /**
     * 
     * @param msg
     * @throws DcerpcException
     * @throws IOException
     */
    public void sendrecv ( DcerpcMessage msg ) throws DcerpcException, IOException {
        if ( this.state == 0 ) {
            bind();
        }
        byte[] inB = this.transportContext.getBufferCache().getBuffer();
        byte[] out = this.transportContext.getBufferCache().getBuffer();
        try {
            NdrBuffer buf = encodeMessage(msg, out);
            int off = sendFragments(msg, out, buf);

            // last fragment gets written (possibly) using transact/call semantics
            int have = doSendReceiveFragment(out, off, msg.length, inB);

            if ( have != 0 ) {
                setupReceivedFragment(buf);
                buf.setIndex(0);
                msg.decode_header(buf);
            }

            NdrBuffer msgBuf;
            if ( have == 0 || !msg.isFlagSet(DCERPC_LAST_FRAG) ) {
                msgBuf = new NdrBuffer(receiveMoreFragments(msg, inB), 0);
            }
            else {
                msgBuf = new NdrBuffer(inB, 0);
            }
            msg.decode(msgBuf);
        }
        finally {
            this.transportContext.getBufferCache().releaseBuffer(inB);
            this.transportContext.getBufferCache().releaseBuffer(out);
        }

        DcerpcException de;
        if ( ( de = msg.getResult() ) != null ) {
            throw de;
        }
    }


    /**
     * @param msg
     * @param out
     * @param buf
     * @param off
     * @param tot
     * @return
     * @throws IOException
     */
    private int sendFragments ( DcerpcMessage msg, byte[] out, NdrBuffer buf ) throws IOException {
        int off = 0;
        int tot = buf.getLength() - 24;
        while ( off < tot ) {
            int fragSize = tot - off;
            if ( ( 24 + fragSize ) > this.max_xmit ) {
                // need fragementation
                msg.flags &= ~DCERPC_LAST_FRAG;
                fragSize = this.max_xmit - 24;
            }
            else {
                msg.flags |= DCERPC_LAST_FRAG;
                msg.alloc_hint = fragSize;
            }

            msg.length = 24 + fragSize;

            if ( off > 0 ) {
                msg.flags &= ~DCERPC_FIRST_FRAG;
            }

            if ( ( msg.flags & ( DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG ) ) != ( DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG ) ) {
                buf.start = off;
                buf.reset();
                msg.encode_header(buf);
                buf.enc_ndr_long(msg.alloc_hint);
                buf.enc_ndr_short(0); /* context id */
                buf.enc_ndr_short(msg.getOpnum());
            }

            if ( ( msg.flags & DCERPC_LAST_FRAG ) != DCERPC_LAST_FRAG ) {
                // all fragment but the last get written using read/write semantics
                doSendFragment(out, off, msg.length);
                off += fragSize;
            }
            else {
                return off;
            }
        }
        throw new IOException();
    }


    /**
     * @param msg
     * @param in
     * @param off
     * @param isDirect
     * @return
     * @throws IOException
     * @throws DcerpcException
     * @throws NdrException
     */
    private byte[] receiveMoreFragments ( DcerpcMessage msg, byte[] in ) throws IOException, DcerpcException, NdrException {
        int off = 0;
        int len = msg.ptype == 2 ? msg.length : 24;
        byte[] fragBytes = new byte[this.max_recv];
        NdrBuffer fragBuf = new NdrBuffer(fragBytes, 0);
        while ( !msg.isFlagSet(DCERPC_LAST_FRAG) ) {
            doReceiveFragment(fragBytes);
            setupReceivedFragment(fragBuf);
            fragBuf.reset();
            msg.decode_header(fragBuf);
            int stub_frag_len = msg.length - 24;
            if ( ( off + stub_frag_len ) > in.length ) {
                // shouldn't happen if alloc_hint is correct or greater
                byte[] tmp = new byte[off + stub_frag_len];
                System.arraycopy(in, 0, tmp, 0, len);
                in = tmp;
            }
            System.arraycopy(fragBytes, 24, in, len, stub_frag_len);
            len += stub_frag_len;
        }
        return in;
    }


    /**
     * @param fbuf
     * @throws DcerpcException
     */
    private void setupReceivedFragment ( NdrBuffer fbuf ) throws DcerpcException {
        fbuf.reset();
        fbuf.setIndex(8);
        fbuf.setLength(fbuf.dec_ndr_short());

        if ( this.securityProvider != null ) {
            this.securityProvider.unwrap(fbuf);
        }
    }


    /**
     * @param msg
     * @param out
     * @return
     * @throws NdrException
     * @throws DcerpcException
     */
    private NdrBuffer encodeMessage ( DcerpcMessage msg, byte[] out ) throws NdrException, DcerpcException {
        NdrBuffer buf = new NdrBuffer(out, 0);

        msg.flags = DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG;
        msg.call_id = call_id.incrementAndGet();

        msg.encode(buf);

        if ( this.securityProvider != null ) {
            buf.setIndex(0);
            this.securityProvider.wrap(buf);
        }
        return buf;
    }


    /**
     * 
     * @param securityProvider
     */
    public void setDcerpcSecurityProvider ( DcerpcSecurityProvider securityProvider ) {
        this.securityProvider = securityProvider;
    }


    /**
     * 
     * @return the server connected to
     */
    public abstract String getServer ();


    /**
     * @return the server resolved by DFS
     */
    public abstract String getServerWithDfs ();


    /**
     * @return the transport context used
     */
    public abstract CIFSContext getTransportContext ();


    /**
     * 
     * @return session key of the underlying smb session
     * @throws CIFSException
     */
    public abstract byte[] getSessionKey () throws CIFSException;


    @Override
    public String toString () {
        return this.binding.toString();
    }


    protected abstract void doSendFragment ( byte[] buf, int off, int length ) throws IOException;


    protected abstract int doReceiveFragment ( byte[] buf ) throws IOException;


    protected abstract int doSendReceiveFragment ( byte[] out, int off, int length, byte[] inB ) throws IOException;


    @Override
    public void close () throws IOException {
        this.state = 0;
    }

}
