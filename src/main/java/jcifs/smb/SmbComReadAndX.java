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


class SmbComReadAndX extends AndXServerMessageBlock {

    private long offset;
    private int fid, openTimeout;
    int maxCount, minCount, remaining;


    SmbComReadAndX () {
        super(null);
        this.command = SMB_COM_READ_ANDX;
        this.openTimeout = 0xFFFFFFFF;
    }


    SmbComReadAndX ( Configuration config, int fid, long offset, int maxCount, ServerMessageBlock andx ) {
        super(config, andx);
        this.fid = fid;
        this.offset = offset;
        this.maxCount = this.minCount = maxCount;
        this.command = SMB_COM_READ_ANDX;
        this.openTimeout = 0xFFFFFFFF;
    }


    void setParam ( int fid, long offset, int maxCount ) {
        this.fid = fid;
        this.offset = offset;
        this.maxCount = this.minCount = maxCount;
    }


    @Override
    int getBatchLimit ( Configuration cfg, byte cmd ) {
        return cmd == SMB_COM_CLOSE ? cfg.getBatchLimit("ReadAndX.Close") : 0;
    }


    @Override
    int writeParameterWordsWireFormat ( byte[] dst, int dstIndex ) {
        int start = dstIndex;

        SMBUtil.writeInt2(this.fid, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt4(this.offset, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt2(this.maxCount, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt2(this.minCount, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt4(this.openTimeout, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt2(this.remaining, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt4(this.offset >> 32, dst, dstIndex);
        dstIndex += 4;

        return dstIndex - start;
    }


    @Override
    int writeBytesWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    int readParameterWordsWireFormat ( byte[] buffer, int bufferIndex ) {
        return 0;
    }


    @Override
    int readBytesWireFormat ( byte[] buffer, int bufferIndex ) {
        return 0;
    }


    @Override
    public String toString () {
        return new String(
            "SmbComReadAndX[" + super.toString() + ",fid=" + this.fid + ",offset=" + this.offset + ",maxCount=" + this.maxCount + ",minCount="
                    + this.minCount + ",openTimeout=" + this.openTimeout + ",remaining=" + this.remaining + ",offset=" + this.offset + "]");
    }
}
