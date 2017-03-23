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

import jcifs.CIFSException;


class TransactCallNamedPipeOutputStream extends SmbPipeOutputStream {

    private String path;
    private SmbPipeHandleImpl handle;
    private byte[] tmp = new byte[1];


    TransactCallNamedPipeOutputStream ( SmbPipeHandleImpl handle, SmbTreeHandleImpl th ) throws CIFSException {
        super(handle, th);
        this.handle = handle;
        this.path = handle.getPipe().getLocator().getUNCPath();
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

        try ( SmbTreeHandleImpl th = this.handle.ensureTreeConnected() ) {
            th.send(new TransWaitNamedPipe(th.getConfig(), this.path), new TransWaitNamedPipeResponse(th.getConfig()));
            th.send(new TransCallNamedPipe(th.getConfig(), this.path, b, off, len), new TransCallNamedPipeResponse(th.getConfig(), this.handle));
        }
    }
}
