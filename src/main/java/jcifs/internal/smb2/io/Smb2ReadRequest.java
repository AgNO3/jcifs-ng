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
public class Smb2ReadRequest extends ServerMessageBlock2Request<Smb2ReadResponse> implements RequestWithFileId {

    /**
     * 
     */
    public static byte SMB2_READFLAG_READ_UNBUFFERED = 0x1;
    /**
     * 
     */
    public static int SMB2_CHANNEL_NONE = 0x0;
    /**
     * 
     */
    public static int SMB2_CHANNEL_RDMA_V1 = 0x1;
    /**
     * 
     */
    public static int SMB2_CHANNEL_RDMA_V1_INVALIDATE = 0x2;

    private byte[] fileId;
    private final byte[] outputBuffer;
    private final int outputBufferOffset;
    private byte padding;
    private byte readFlags;
    private int readLength;
    private long offset;
    private int minimumCount;
    private int channel;
    private int remainingBytes;


    /**
     * @param config
     * @param fileId
     * @param outputBuffer
     * @param outputBufferOffset
     */
    public Smb2ReadRequest ( Configuration config, byte[] fileId, byte[] outputBuffer, int outputBufferOffset ) {
        super(config, SMB2_READ);
        this.fileId = fileId;
        this.outputBuffer = outputBuffer;
        this.outputBufferOffset = outputBufferOffset;
    }


    @Override
    protected Smb2ReadResponse createResponse ( CIFSContext tc, ServerMessageBlock2Request<Smb2ReadResponse> req ) {
        return new Smb2ReadResponse(tc.getConfig(), this.outputBuffer, this.outputBufferOffset);
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


    /**
     * @param padding
     *            the padding to set
     */
    public void setPadding ( byte padding ) {
        this.padding = padding;
    }


    /**
     * @param readFlags
     *            the readFlags to set
     */
    public void setReadFlags ( byte readFlags ) {
        this.readFlags = readFlags;
    }


    /**
     * @param readLength
     *            the readLength to set
     */
    public void setReadLength ( int readLength ) {
        this.readLength = readLength;
    }


    /**
     * @param offset
     *            the offset to set
     */
    public void setOffset ( long offset ) {
        this.offset = offset;
    }


    /**
     * @param minimumCount
     *            the minimumCount to set
     */
    public void setMinimumCount ( int minimumCount ) {
        this.minimumCount = minimumCount;
    }


    /**
     * @param remainingBytes
     *            the remainingBytes to set
     */
    public void setRemainingBytes ( int remainingBytes ) {
        this.remainingBytes = remainingBytes;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockRequest#size()
     */
    @Override
    public int size () {
        return size8(Smb2Constants.SMB2_HEADER_LENGTH + 49);
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
        dst[ dstIndex + 2 ] = this.padding;
        dst[ dstIndex + 3 ] = this.readFlags;
        dstIndex += 4;
        SMBUtil.writeInt4(this.readLength, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt8(this.offset, dst, dstIndex);
        dstIndex += 8;
        System.arraycopy(this.fileId, 0, dst, dstIndex, 16);
        dstIndex += 16;
        SMBUtil.writeInt4(this.minimumCount, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt4(this.channel, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt4(this.remainingBytes, dst, dstIndex);
        dstIndex += 4;

        // ReadChannelInfo
        SMBUtil.writeInt2(0, dst, dstIndex);
        SMBUtil.writeInt2(0, dst, dstIndex + 2);
        dstIndex += 4;

        // one byte in buffer must be zero
        dst[ dstIndex ] = 0;
        dstIndex += 1;

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
