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


import jcifs.Configuration;


public class BufferCache {

    private final Object[] cache;
    private int freeBuffers = 0;


    public BufferCache ( Configuration cfg ) {
        this(cfg.getBufferCacheSize());
    }


    /**
     * 
     */
    public BufferCache ( int maxBuffers ) {
        this.cache = new Object[maxBuffers];
    }


    public byte[] getBuffer () {
        synchronized ( this.cache ) {
            byte[] buf;

            if ( this.freeBuffers > 0 ) {
                for ( int i = 0; i < this.cache.length; i++ ) {
                    if ( this.cache[ i ] != null ) {
                        buf = (byte[]) this.cache[ i ];
                        this.cache[ i ] = null;
                        this.freeBuffers--;
                        return buf;
                    }
                }
            }
            return new byte[SmbComTransaction.TRANSACTION_BUF_SIZE];
        }
    }


    void getBuffers ( SmbComTransaction req, SmbComTransactionResponse rsp ) {
        synchronized ( this.cache ) {
            req.txn_buf = getBuffer();
            rsp.txn_buf = getBuffer();
        }
    }


    public void releaseBuffer ( byte[] buf ) {
        synchronized ( this.cache ) {
            if ( this.freeBuffers < this.cache.length ) {
                for ( int i = 0; i < this.cache.length; i++ ) {
                    if ( this.cache[ i ] == null ) {
                        this.cache[ i ] = buf;
                        this.freeBuffers++;
                        return;
                    }
                }
            }
        }
    }
}
