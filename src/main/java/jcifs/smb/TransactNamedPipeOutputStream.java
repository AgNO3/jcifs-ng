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


import java.io.IOException;

import jcifs.Configuration;


class TransactNamedPipeOutputStream extends SmbFileOutputStream {

    private String path;
    private SmbNamedPipe pipe;
    private byte[] tmp = new byte[1];
    private boolean dcePipe;
    private Configuration config;


    TransactNamedPipeOutputStream ( SmbNamedPipe pipe ) throws IOException {
        super(pipe, false, ( pipe.pipeType & 0xFFFF00FF ) | SmbFile.O_EXCL);
        this.config = pipe.getTransportContext().getConfig();
        this.pipe = pipe;
        this.dcePipe = ( pipe.pipeType & SmbNamedPipe.PIPE_TYPE_DCE_TRANSACT ) == SmbNamedPipe.PIPE_TYPE_DCE_TRANSACT;
        this.path = pipe.unc;
    }


    @Override
    public void close () throws IOException {
        this.pipe.close();
    }


    @Override
    public void write ( int b ) throws IOException {
        this.tmp[ 0 ] = (byte) b;
        write(this.tmp, 0, 1);
    }


    @Override
    public void write ( byte[] b ) throws IOException {
        write(b, 0, b.length);
    }


    @Override
    public void write ( byte[] b, int off, int len ) throws IOException {
        if ( len < 0 ) {
            len = 0;
        }

        if ( ( this.pipe.pipeType & SmbNamedPipe.PIPE_TYPE_CALL ) == SmbNamedPipe.PIPE_TYPE_CALL ) {
            this.pipe.send(new TransWaitNamedPipe(this.config, this.path), new TransWaitNamedPipeResponse(this.config));
            this.pipe.send(new TransCallNamedPipe(this.config, this.path, b, off, len), new TransCallNamedPipeResponse(this.config, this.pipe));
        }
        else if ( ( this.pipe.pipeType & SmbNamedPipe.PIPE_TYPE_TRANSACT ) == SmbNamedPipe.PIPE_TYPE_TRANSACT ) {
            ensureOpen();
            TransTransactNamedPipe req = new TransTransactNamedPipe(this.config, this.pipe.fid, b, off, len);
            if ( this.dcePipe ) {
                req.maxDataCount = 1024;
            }
            this.pipe.send(req, new TransTransactNamedPipeResponse(this.config, this.pipe));
        }
    }
}
