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
import jcifs.internal.fscc.FileInformation;
import jcifs.internal.smb2.RequestWithFileId;
import jcifs.internal.smb2.ServerMessageBlock2Request;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.util.SMBUtil;


/**
 * @author mbechler
 *
 */
public class Smb2SetInfoRequest extends ServerMessageBlock2Request<Smb2SetInfoResponse> implements RequestWithFileId {

    private byte[] fileId;
    private byte infoType;
    private byte fileInfoClass;
    private int additionalInformation;
    private Encodable info;


    /**
     * 
     * @param config
     */
    public Smb2SetInfoRequest ( Configuration config ) {
        this(config, Smb2Constants.UNSPECIFIED_FILEID);
    }


    /**
     * @param config
     * @param fileId
     */
    public Smb2SetInfoRequest ( Configuration config, byte[] fileId ) {
        super(config, SMB2_SET_INFO);
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
    public void setInfoType ( byte infoType ) {
        this.infoType = infoType;
    }


    /**
     * @param fileInfoClass
     *            the fileInfoClass to set
     */
    public void setFileInfoClass ( byte fileInfoClass ) {
        this.fileInfoClass = fileInfoClass;
    }


    /**
     * @param additionalInformation
     *            the additionalInformation to set
     */
    public void setAdditionalInformation ( int additionalInformation ) {
        this.additionalInformation = additionalInformation;
    }


    /**
     * 
     * @param fi
     */
    public <T extends FileInformation & Encodable> void setFileInformation ( T fi ) {
        setInfoType(Smb2Constants.SMB2_0_INFO_FILE);
        setFileInfoClass(fi.getFileInformationLevel());
        setInfo(fi);
    }


    /**
     * @param info
     *            the info to set
     */
    public void setInfo ( Encodable info ) {
        this.info = info;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2Request#createResponse(jcifs.CIFSContext,
     *      jcifs.internal.smb2.ServerMessageBlock2Request)
     */
    @Override
    protected Smb2SetInfoResponse createResponse ( CIFSContext tc, ServerMessageBlock2Request<Smb2SetInfoResponse> req ) {
        return new Smb2SetInfoResponse(tc.getConfig());
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockRequest#size()
     */
    @Override
    public int size () {
        return size8(Smb2Constants.SMB2_HEADER_LENGTH + 32 + this.info.size());
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#writeBytesWireFormat(byte[], int)
     */
    @Override
    protected int writeBytesWireFormat ( byte[] dst, int dstIndex ) {
        int start = dstIndex;
        SMBUtil.writeInt2(33, dst, dstIndex);
        dst[ dstIndex + 2 ] = this.infoType;
        dst[ dstIndex + 3 ] = this.fileInfoClass;
        dstIndex += 4;

        int bufferLengthOffset = dstIndex;
        dstIndex += 4;
        int bufferOffsetOffset = dstIndex;
        dstIndex += 4;

        SMBUtil.writeInt4(this.additionalInformation, dst, dstIndex);
        dstIndex += 4;

        System.arraycopy(this.fileId, 0, dst, dstIndex, 16);
        dstIndex += 16;

        SMBUtil.writeInt2(dstIndex - getHeaderStart(), dst, bufferOffsetOffset);
        int len = this.info.encode(dst, dstIndex);
        SMBUtil.writeInt4(len, dst, bufferLengthOffset);
        dstIndex += len;
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
