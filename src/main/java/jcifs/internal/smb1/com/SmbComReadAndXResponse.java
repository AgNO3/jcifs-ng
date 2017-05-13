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
import jcifs.internal.util.SMBUtil;


/**
 *
 */
public class SmbComReadAndXResponse extends AndXServerMessageBlock {

    private byte[] data;
    private int offset, dataCompactionMode, dataLength, dataOffset;


    /**
     * 
     * @param config
     */
    public SmbComReadAndXResponse ( Configuration config ) {
        super(config);
    }


    /**
     * 
     * @param config
     * @param b
     * @param off
     */
    public SmbComReadAndXResponse ( Configuration config, byte[] b, int off ) {
        super(config);
        this.data = b;
        this.offset = off;
    }


    void setParam ( byte[] b, int off ) {
        this.data = b;
        this.offset = off;
    }


    /**
     * 
     * @return the read data
     */
    public final byte[] getData () {
        return this.data;
    }


    /**
     * @return the offset
     */
    public final int getOffset () {
        return this.offset;
    }


    /**
     * @param n
     */
    public void adjustOffset ( int n ) {
        this.offset += n;
    }


    /**
     * @return the dataLength
     */
    public final int getDataLength () {
        return this.dataLength;
    }


    /**
     * @return the dataOffset
     */
    public final int getDataOffset () {
        return this.dataOffset;
    }


    @Override
    protected int writeParameterWordsWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    protected int writeBytesWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    protected int readParameterWordsWireFormat ( byte[] buffer, int bufferIndex ) {
        int start = bufferIndex;

        bufferIndex += 2; // reserved
        this.dataCompactionMode = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 4; // 2 reserved
        this.dataLength = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.dataOffset = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 12; // 10 reserved

        return bufferIndex - start;
    }


    @Override
    protected int readBytesWireFormat ( byte[] buffer, int bufferIndex ) {
        // handled special in SmbTransport.doRecv()
        return 0;
    }


    @Override
    public String toString () {
        return new String(
            "SmbComReadAndXResponse[" + super.toString() + ",dataCompactionMode=" + this.dataCompactionMode + ",dataLength=" + this.dataLength
                    + ",dataOffset=" + this.dataOffset + "]");
    }

}
