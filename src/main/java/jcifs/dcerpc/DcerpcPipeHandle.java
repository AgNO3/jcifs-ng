/* jcifs msrpc client library in Java
 * Copyright (C) 2006  "Michael B. Allen" <jcifs at samba dot org>
 *                     "Eric Glass" <jcifs at samba dot org>
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

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.SmbPipeResource;
import jcifs.smb.SmbNamedPipe;
import jcifs.smb.SmbPipeHandleInternal;
import jcifs.util.Encdec;


/**
 *
 */
public class DcerpcPipeHandle extends DcerpcHandle {

    /* This 0x20000 bit is going to get chopped! */
    final static int pipeFlags = ( 0x2019F << 16 ) | SmbPipeResource.PIPE_TYPE_RDWR | SmbPipeResource.PIPE_TYPE_DCE_TRANSACT;

    private SmbNamedPipe pipe;
    private SmbPipeHandleInternal handle;


    /**
     * @param url
     * @param tc
     * @param unshared
     * @throws DcerpcException
     * @throws MalformedURLException
     */
    public DcerpcPipeHandle ( String url, CIFSContext tc, boolean unshared ) throws DcerpcException, MalformedURLException {
        super(tc, DcerpcHandle.parseBinding(url));
        this.pipe = new SmbNamedPipe(makePipeUrl(), pipeFlags, unshared, tc);
        this.handle = this.pipe.openPipe().unwrap(SmbPipeHandleInternal.class);
    }


    private String makePipeUrl () {
        DcerpcBinding binding = getBinding();
        String url = "smb://" + binding.getServer() + "/IPC$/" + binding.getEndpoint().substring(6);

        String params = "", server, address;
        server = (String) binding.getOption("server");
        if ( server != null )
            params += "&server=" + server;
        address = (String) binding.getOption("address");
        if ( server != null )
            params += "&address=" + address;
        if ( params.length() > 0 )
            url += "?" + params.substring(1);

        return url;
    }


    @Override
    public CIFSContext getTransportContext () {
        return this.pipe.getContext();
    }


    @Override
    public String getServer () {
        return this.pipe.getLocator().getServer();
    }


    @Override
    public String getServerWithDfs () {
        return this.pipe.getLocator().getServerWithDfs();
    }


    @Override
    public byte[] getSessionKey () throws CIFSException {
        return this.handle.getSessionKey();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.dcerpc.DcerpcHandle#doSendReceiveFragment(byte[], int, int, byte[])
     */
    @Override
    protected int doSendReceiveFragment ( byte[] buf, int off, int length, byte[] inB ) throws IOException {
        if ( this.handle.isStale() ) {
            throw new IOException("DCERPC pipe is no longer open");
        }

        return this.handle.sendrecv(buf, off, length, inB, getMaxRecv());
    }


    @Override
    protected void doSendFragment ( byte[] buf, int off, int length ) throws IOException {
        if ( this.handle.isStale() ) {
            throw new IOException("DCERPC pipe is no longer open");
        }
        this.handle.send(buf, off, length);
    }


    @Override
    protected int doReceiveFragment ( byte[] buf ) throws IOException {
        if ( buf.length < getMaxRecv() ) {
            throw new IllegalArgumentException("buffer too small");
        }

        int off = this.handle.recv(buf, 0, buf.length);
        if ( buf[ 0 ] != 5 && buf[ 1 ] != 0 ) {
            throw new IOException("Unexpected DCERPC PDU header");
        }

        int length = Encdec.dec_uint16le(buf, 8);
        if ( length > getMaxRecv() ) {
            throw new IOException("Unexpected fragment length: " + length);
        }

        while ( off < length ) {
            off += this.handle.recv(buf, off, length - off);
        }
        return off;
    }


    @Override
    public void close () throws IOException {
        super.close();
        try {
            this.handle.close();
        }
        finally {
            this.pipe.close();
        }
    }
}
