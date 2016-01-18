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
import jcifs.smb.SmbFileInputStream;
import jcifs.smb.SmbFileOutputStream;
import jcifs.smb.SmbNamedPipe;
import jcifs.util.Encdec;


public class DcerpcPipeHandle extends DcerpcHandle {

    /* This 0x20000 bit is going to get chopped! */
    final static int pipeFlags = ( 0x2019F << 16 ) | SmbNamedPipe.PIPE_TYPE_RDWR | SmbNamedPipe.PIPE_TYPE_DCE_TRANSACT;

    SmbNamedPipe pipe;
    SmbFileInputStream in = null;
    SmbFileOutputStream out = null;
    boolean isStart = true;


    /**
     * @param url
     * @param tc
     */
    public DcerpcPipeHandle ( String url, CIFSContext tc ) throws DcerpcException, MalformedURLException {
        super(tc, DcerpcHandle.parseBinding(url));
        this.pipe = new SmbNamedPipe(makePipeUrl(), pipeFlags, tc);
    }


    private String makePipeUrl () {
        String url = "smb://" + this.getBinding().getServer() + "/IPC$/" + this.getBinding().getEndpoint().substring(6);

        String params = "", server, address;
        server = (String) this.getBinding().getOption("server");
        if ( server != null )
            params += "&server=" + server;
        address = (String) this.getBinding().getOption("address");
        if ( server != null )
            params += "&address=" + address;
        if ( params.length() > 0 )
            url += "?" + params.substring(1);

        return url;
    }


    @Override
    protected void doSendFragment ( byte[] buf, int off, int length, boolean isDirect ) throws IOException {
        if ( this.out != null && this.out.isOpen() == false )
            throw new IOException("DCERPC pipe is no longer open");

        if ( this.in == null )
            this.in = (SmbFileInputStream) this.pipe.getNamedPipeInputStream();
        if ( this.out == null )
            this.out = (SmbFileOutputStream) this.pipe.getNamedPipeOutputStream();
        if ( isDirect ) {
            this.out.writeDirect(buf, off, length, 1);
            return;
        }
        this.out.write(buf, off, length);
    }


    @Override
    protected void doReceiveFragment ( byte[] buf, boolean isDirect ) throws IOException {
        int off, flags, length;

        if ( buf.length < this.getMaxRecv() )
            throw new IllegalArgumentException("buffer too small");

        if ( this.isStart && !isDirect ) { // start of new frag, do trans
            off = this.in.read(buf, 0, 1024);
        }
        else {
            off = this.in.readDirect(buf, 0, buf.length);
        }

        if ( buf[ 0 ] != 5 && buf[ 1 ] != 0 )
            throw new IOException("Unexpected DCERPC PDU header");

        flags = buf[ 3 ] & 0xFF;
        // next read is start of new frag
        this.isStart = ( flags & DCERPC_LAST_FRAG ) == DCERPC_LAST_FRAG;

        length = Encdec.dec_uint16le(buf, 8);
        if ( length > this.getMaxRecv() )
            throw new IOException("Unexpected fragment length: " + length);

        while ( off < length ) {
            off += this.in.readDirect(buf, off, length - off);
        }
    }


    @Override
    public void close () throws IOException {
        super.close();
        if ( this.out != null )
            this.out.close();
    }
}
