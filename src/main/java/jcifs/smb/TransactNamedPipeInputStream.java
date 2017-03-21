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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


class TransactNamedPipeInputStream extends SmbPipeInputStream {

    private static final Logger log = LoggerFactory.getLogger(TransactNamedPipeInputStream.class);

    private static final int INIT_PIPE_SIZE = 4096;

    private byte[] pipe_buf = new byte[INIT_PIPE_SIZE];
    private int beg_idx, nxt_idx, used;
    Object lock;


    TransactNamedPipeInputStream ( SmbPipeHandleImpl pipe, SmbTreeHandleImpl th ) throws SmbException {
        super(pipe, th);
        this.lock = new Object();
    }


    @Override
    public int read () throws IOException {
        int result = -1;

        synchronized ( this.lock ) {
            try {
                while ( this.used == 0 ) {
                    this.lock.wait();
                }
            }
            catch ( InterruptedException ie ) {
                throw new IOException(ie.getMessage());
            }
            result = this.pipe_buf[ this.beg_idx ] & 0xFF;
            this.beg_idx = ( this.beg_idx + 1 ) % this.pipe_buf.length;
        }
        return result;
    }


    @Override
    public int read ( byte[] b ) throws IOException {
        return read(b, 0, b.length);
    }


    @Override
    public int read ( byte[] b, int off, int len ) throws IOException {
        int result = -1;
        int i;

        if ( len <= 0 ) {
            return 0;
        }
        synchronized ( this.lock ) {
            try {
                while ( this.used == 0 ) {
                    this.lock.wait();
                }
            }
            catch ( InterruptedException ie ) {
                throw new IOException(ie.getMessage());
            }
            i = this.pipe_buf.length - this.beg_idx;
            result = len > this.used ? this.used : len;
            if ( this.used > i && result > i ) {
                System.arraycopy(this.pipe_buf, this.beg_idx, b, off, i);
                off += i;
                System.arraycopy(this.pipe_buf, 0, b, off, result - i);
            }
            else {
                System.arraycopy(this.pipe_buf, this.beg_idx, b, off, result);
            }
            this.used -= result;
            this.beg_idx = ( this.beg_idx + result ) % this.pipe_buf.length;
        }

        return result;
    }


    @Override
    public int available () throws IOException {
        if ( log.isDebugEnabled() )
            log.debug("Named Pipe available() does not apply to TRANSACT Named Pipes");
        return 0;
    }


    int receive ( byte[] b, int off, int len ) {
        int i;

        if ( len > ( this.pipe_buf.length - this.used ) ) {
            byte[] tmp;
            int new_size;

            new_size = this.pipe_buf.length * 2;
            if ( len > ( new_size - this.used ) ) {
                new_size = len + this.used;
            }
            tmp = this.pipe_buf;
            this.pipe_buf = new byte[new_size];
            i = tmp.length - this.beg_idx;
            if ( this.used > i ) { /* 2 chunks */
                System.arraycopy(tmp, this.beg_idx, this.pipe_buf, 0, i);
                System.arraycopy(tmp, 0, this.pipe_buf, i, this.used - i);
            }
            else {
                System.arraycopy(tmp, this.beg_idx, this.pipe_buf, 0, this.used);
            }
            this.beg_idx = 0;
            this.nxt_idx = this.used;
            tmp = null;
        }

        i = this.pipe_buf.length - this.nxt_idx;
        if ( len > i ) {
            System.arraycopy(b, off, this.pipe_buf, this.nxt_idx, i);
            off += i;
            System.arraycopy(b, off, this.pipe_buf, 0, len - i);
        }
        else {
            System.arraycopy(b, off, this.pipe_buf, this.nxt_idx, len);
        }
        this.nxt_idx = ( this.nxt_idx + len ) % this.pipe_buf.length;
        this.used += len;
        return len;
    }


    public int dce_read ( byte[] b, int off, int len ) throws IOException {
        return super.read(b, off, len);
    }
}
