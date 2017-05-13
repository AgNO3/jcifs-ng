/* jcifs smb client library in Java
 * Copyright (C) 2003  "Michael B. Allen" <jcifs at samba dot org>
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

package jcifs.internal.smb1.com;


import jcifs.Configuration;
import jcifs.internal.smb1.ServerMessageBlock;
import jcifs.internal.util.SMBUtil;


/**
 * 
 */
public class SmbComWrite extends ServerMessageBlock {

    private int fid, count, offset, remaining, off;
    private byte[] b;


    /**
     * 
     * @param config
     */
    public SmbComWrite ( Configuration config ) {
        super(config, SMB_COM_WRITE);
    }


    /**
     * 
     * @param config
     * @param fid
     * @param offset
     * @param remaining
     * @param b
     * @param off
     * @param len
     */
    public SmbComWrite ( Configuration config, int fid, int offset, int remaining, byte[] b, int off, int len ) {
        super(config, SMB_COM_WRITE);
        this.fid = fid;
        this.count = len;
        this.offset = offset;
        this.remaining = remaining;
        this.b = b;
        this.off = off;
    }


    /**
     * 
     * @param fid
     * @param offset
     * @param remaining
     * @param b
     * @param off
     * @param len
     */
    public final void setParam ( int fid, long offset, int remaining, byte[] b, int off, int len ) {
        this.fid = fid;
        this.offset = (int) ( offset & 0xFFFFFFFFL );
        this.remaining = remaining;
        this.b = b;
        this.off = off;
        this.count = len;
        this.digest = null; /*
                             * otherwise recycled commands
                             * like writeandx will choke if session
                             * closes in between
                             */
    }


    @Override
    protected int writeParameterWordsWireFormat ( byte[] dst, int dstIndex ) {
        int start = dstIndex;

        SMBUtil.writeInt2(this.fid, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt2(this.count, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt4(this.offset, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt2(this.remaining, dst, dstIndex);
        dstIndex += 2;

        return dstIndex - start;
    }


    @Override
    protected int writeBytesWireFormat ( byte[] dst, int dstIndex ) {
        int start = dstIndex;

        dst[ dstIndex++ ] = (byte) 0x01; /* BufferFormat */
        SMBUtil.writeInt2(this.count, dst, dstIndex); /* DataLength? */
        dstIndex += 2;
        System.arraycopy(this.b, this.off, dst, dstIndex, this.count);
        dstIndex += this.count;

        return dstIndex - start;
    }


    @Override
    protected int readParameterWordsWireFormat ( byte[] buffer, int bufferIndex ) {
        return 0;
    }


    @Override
    protected int readBytesWireFormat ( byte[] buffer, int bufferIndex ) {
        return 0;
    }


    @Override
    public String toString () {
        return new String(
            "SmbComWrite[" + super.toString() + ",fid=" + this.fid + ",count=" + this.count + ",offset=" + this.offset + ",remaining="
                    + this.remaining + "]");
    }
}
