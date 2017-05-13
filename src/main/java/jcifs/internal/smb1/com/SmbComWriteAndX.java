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

package jcifs.internal.smb1.com;


import jcifs.Configuration;
import jcifs.internal.smb1.AndXServerMessageBlock;
import jcifs.internal.smb1.ServerMessageBlock;
import jcifs.internal.util.SMBUtil;


/**
 * 
 */
public class SmbComWriteAndX extends AndXServerMessageBlock {

    private int fid, remaining, dataLength, dataOffset, off;
    private byte[] b;
    private long offset;
    private int pad;
    private int writeMode;


    /**
     * 
     * @param config
     */
    public SmbComWriteAndX ( Configuration config ) {
        super(config, SMB_COM_WRITE_ANDX, null);
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
     * @param andx
     */
    public SmbComWriteAndX ( Configuration config, int fid, long offset, int remaining, byte[] b, int off, int len, ServerMessageBlock andx ) {
        super(config, SMB_COM_WRITE_ANDX, andx);
        this.fid = fid;
        this.offset = offset;
        this.remaining = remaining;
        this.b = b;
        this.off = off;
        this.dataLength = len;
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
        this.offset = offset;
        this.remaining = remaining;
        this.b = b;
        this.off = off;
        this.dataLength = len;
        this.digest = null; /*
                             * otherwise recycled commands
                             * like writeandx will choke if session
                             * closes in between
                             */
    }


    /**
     * @param writeMode
     *            the writeMode to set
     */
    public final void setWriteMode ( int writeMode ) {
        this.writeMode = writeMode;
    }


    @Override
    protected int getBatchLimit ( Configuration cfg, byte cmd ) {
        if ( cmd == SMB_COM_READ_ANDX ) {
            return cfg.getBatchLimit("WriteAndX.ReadAndX");
        }
        if ( cmd == SMB_COM_CLOSE ) {
            return cfg.getBatchLimit("WriteAndX.Close");
        }
        return 0;
    }


    @Override
    protected int writeParameterWordsWireFormat ( byte[] dst, int dstIndex ) {
        int start = dstIndex;

        this.dataOffset = ( dstIndex - this.headerStart ) + 26; // 26 = off from here to pad

        this.pad = ( this.dataOffset - this.headerStart ) % 4;
        this.pad = this.pad == 0 ? 0 : 4 - this.pad;
        this.dataOffset += this.pad;

        SMBUtil.writeInt2(this.fid, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt4(this.offset, dst, dstIndex);
        dstIndex += 4;
        for ( int i = 0; i < 4; i++ ) {
            dst[ dstIndex++ ] = (byte) 0xFF;
        }
        SMBUtil.writeInt2(this.writeMode, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt2(this.remaining, dst, dstIndex);
        dstIndex += 2;
        dst[ dstIndex++ ] = (byte) 0x00;
        dst[ dstIndex++ ] = (byte) 0x00;
        SMBUtil.writeInt2(this.dataLength, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt2(this.dataOffset, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt4(this.offset >> 32, dst, dstIndex);
        dstIndex += 4;

        return dstIndex - start;
    }


    @Override
    protected int writeBytesWireFormat ( byte[] dst, int dstIndex ) {
        int start = dstIndex;

        while ( this.pad-- > 0 ) {
            dst[ dstIndex++ ] = (byte) 0xEE;
        }
        System.arraycopy(this.b, this.off, dst, dstIndex, this.dataLength);
        dstIndex += this.dataLength;

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
            "SmbComWriteAndX[" + super.toString() + ",fid=" + this.fid + ",offset=" + this.offset + ",writeMode=" + this.writeMode + ",remaining="
                    + this.remaining + ",dataLength=" + this.dataLength + ",dataOffset=" + this.dataOffset + "]");
    }
}
