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
package jcifs.internal.smb2.info;


import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.Encodable;
import jcifs.internal.smb2.RequestWithFileId;
import jcifs.internal.smb2.ServerMessageBlock2Request;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.util.SMBUtil;


/**
 * @author mbechler
 *
 */
public class Smb2QueryInfoRequest extends ServerMessageBlock2Request<Smb2QueryInfoResponse> implements RequestWithFileId {

    private byte infoType;
    private byte fileInfoClass;
    private int outputBufferLength;
    private int additionalInformation;
    private int queryFlags;
    private byte[] fileId;
    private Encodable inputBuffer;


    /**
     * @param config
     */
    public Smb2QueryInfoRequest ( Configuration config ) {
        this(config, Smb2Constants.UNSPECIFIED_FILEID);
    }


    /**
     * @param config
     * @param fileId
     */
    public Smb2QueryInfoRequest ( Configuration config, byte[] fileId ) {
        super(config, SMB2_QUERY_INFO);
        this.outputBufferLength = config.getListSize();
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


    /**
     * @param infoType
     *            the infoType to set
     */
    public final void setInfoType ( byte infoType ) {
        this.infoType = infoType;
    }


    /**
     * @param fileInfoClass
     *            the fileInfoClass to set
     */
    public final void setFileInfoClass ( byte fileInfoClass ) {
        setInfoType(Smb2Constants.SMB2_0_INFO_FILE);
        this.fileInfoClass = fileInfoClass;
    }


    /**
     * @param fileInfoClass
     *            the fileInfoClass to set
     */
    public final void setFilesystemInfoClass ( byte fileInfoClass ) {
        setInfoType(Smb2Constants.SMB2_0_INFO_FILESYSTEM);
        this.fileInfoClass = fileInfoClass;
    }


    /**
     * @param additionalInformation
     *            the additionalInformation to set
     */
    public final void setAdditionalInformation ( int additionalInformation ) {
        this.additionalInformation = additionalInformation;
    }


    /**
     * @param queryFlags
     *            the queryFlags to set
     */
    public final void setQueryFlags ( int queryFlags ) {
        this.queryFlags = queryFlags;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2Request#createResponse(jcifs.CIFSContext,
     *      jcifs.internal.smb2.ServerMessageBlock2Request)
     */
    @Override
    protected Smb2QueryInfoResponse createResponse ( CIFSContext tc, ServerMessageBlock2Request<Smb2QueryInfoResponse> req ) {
        return new Smb2QueryInfoResponse(tc.getConfig(), this.infoType, this.fileInfoClass);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockRequest#size()
     */
    @Override
    public int size () {
        int size = Smb2Constants.SMB2_HEADER_LENGTH + 40;
        if ( this.inputBuffer != null ) {
            size += this.inputBuffer.size();
        }
        return size8(size);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#writeBytesWireFormat(byte[], int)
     */
    @Override
    protected int writeBytesWireFormat ( byte[] dst, int dstIndex ) {
        int start = dstIndex;

        SMBUtil.writeInt2(41, dst, dstIndex);
        dst[ dstIndex + 2 ] = this.infoType;
        dst[ dstIndex + 3 ] = this.fileInfoClass;
        dstIndex += 4;

        SMBUtil.writeInt4(this.outputBufferLength, dst, dstIndex);
        dstIndex += 4;
        int inBufferOffsetOffset = dstIndex;
        dstIndex += 4;
        int inBufferLengthOffset = dstIndex;
        dstIndex += 4;
        SMBUtil.writeInt4(this.additionalInformation, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt4(this.queryFlags, dst, dstIndex);
        dstIndex += 4;
        System.arraycopy(this.fileId, 0, dst, dstIndex, 16);
        dstIndex += 16;

        if ( this.inputBuffer == null ) {
            SMBUtil.writeInt2(0, dst, inBufferOffsetOffset);
            SMBUtil.writeInt4(0, dst, inBufferLengthOffset);
        }
        else {
            SMBUtil.writeInt2(dstIndex - getHeaderStart(), dst, inBufferOffsetOffset);
            int len = this.inputBuffer.encode(dst, dstIndex);
            SMBUtil.writeInt4(len, dst, inBufferLengthOffset);
            dstIndex += len;
        }
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
