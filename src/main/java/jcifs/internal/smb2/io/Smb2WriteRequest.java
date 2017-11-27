/*
 * © 2017 AgNO3 Gmbh & Co. KG
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
package jcifs.internal.smb2.io;


import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.internal.smb2.RequestWithFileId;
import jcifs.internal.smb2.ServerMessageBlock2Request;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.util.SMBUtil;


/**
 * @author mbechler
 *
 */
public class Smb2WriteRequest extends ServerMessageBlock2Request<Smb2WriteResponse> implements RequestWithFileId {

    /**
     * 
     */
    public static final int OVERHEAD = Smb2Constants.SMB2_HEADER_LENGTH + 48;

    private byte[] data;
    private int dataOffset;
    private int dataLength;

    private byte[] fileId;
    private long offset;
    private int channel;
    private int remainingBytes;
    private int writeFlags;


    /**
     * @param config
     * @param fileId
     */
    public Smb2WriteRequest ( Configuration config, byte[] fileId ) {
        super(config, SMB2_WRITE);
        this.fileId = fileId;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.RequestWithFileId#setFileId(byte[])
     */
    @Override
    public void setFileId ( byte[] fileId ) {
        this.fileId = fileId;
    }


    @Override
    protected Smb2WriteResponse createResponse ( CIFSContext tc, ServerMessageBlock2Request<Smb2WriteResponse> req ) {
        return new Smb2WriteResponse(tc.getConfig());
    }


    /**
     * @param data
     *            the data to set
     * @param offset
     * @param length
     */
    public void setData ( byte[] data, int offset, int length ) {
        this.data = data;
        this.dataOffset = offset;
        this.dataLength = length;
    }


    /**
     * @param remainingBytes
     *            the remainingBytes to set
     */
    public void setRemainingBytes ( int remainingBytes ) {
        this.remainingBytes = remainingBytes;
    }


    /**
     * @param writeFlags
     *            the writeFlags to set
     */
    public void setWriteFlags ( int writeFlags ) {
        this.writeFlags = writeFlags;
    }


    /**
     * @param offset
     *            the offset to set
     */
    public void setOffset ( long offset ) {
        this.offset = offset;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockRequest#size()
     */
    @Override
    public int size () {
        return size8(Smb2Constants.SMB2_HEADER_LENGTH + 48 + this.dataLength);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#writeBytesWireFormat(byte[], int)
     */
    @Override
    protected int writeBytesWireFormat ( byte[] dst, int dstIndex ) {
        int start = dstIndex;
        SMBUtil.writeInt2(49, dst, dstIndex);
        int dataOffsetOffset = dstIndex + 2;
        dstIndex += 4;
        SMBUtil.writeInt4(this.dataLength, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt8(this.offset, dst, dstIndex);
        dstIndex += 8;
        System.arraycopy(this.fileId, 0, dst, dstIndex, 16);
        dstIndex += 16;
        SMBUtil.writeInt4(this.channel, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt4(this.remainingBytes, dst, dstIndex);
        dstIndex += 4;

        SMBUtil.writeInt2(0, dst, dstIndex); // writeChannelInfoOffset
        SMBUtil.writeInt2(0, dst, dstIndex + 2); // writeChannelInfoLength
        dstIndex += 4;

        SMBUtil.writeInt4(this.writeFlags, dst, dstIndex);
        dstIndex += 4;

        SMBUtil.writeInt2(dstIndex - getHeaderStart(), dst, dataOffsetOffset);

        if ( dstIndex + this.dataLength > dst.length ) {
            throw new IllegalArgumentException(
                String.format("Data exceeds buffer size ( remain buffer: %d data length: %d)", dst.length - dstIndex, this.dataLength));
        }

        System.arraycopy(this.data, this.dataOffset, dst, dstIndex, this.dataLength);
        dstIndex += this.dataLength;
        return dstIndex - start;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#readBytesWireFormat(byte[], int)
     */
    @Override
    protected int readBytesWireFormat ( byte[] buffer, int bufferIndex ) {
        return 0;
    }

}
