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
package jcifs.internal.smb2.ioctl;


import jcifs.Configuration;
import jcifs.Decodable;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.dfs.DfsReferralResponseBuffer;
import jcifs.internal.smb2.ServerMessageBlock2Response;
import jcifs.internal.util.SMBUtil;
import jcifs.smb.NtStatus;
import jcifs.smb.SmbException;


/**
 * @author mbechler
 *
 */
public class Smb2IoctlResponse extends ServerMessageBlock2Response {

    private final byte[] outputBuffer;
    private int ctlCode;
    private byte[] fileId;
    private int ioctlFlags;
    private Decodable outputData;
    private Decodable inputData;
    private int outputLength;


    /**
     * @param config
     */
    public Smb2IoctlResponse ( Configuration config ) {
        super(config);
        this.outputBuffer = null;
    }


    /**
     * @param config
     * @param outputBuffer
     */
    public Smb2IoctlResponse ( Configuration config, byte[] outputBuffer ) {
        super(config);
        this.outputBuffer = outputBuffer;
    }


    /**
     * @param config
     * @param outputBuffer
     * @param ctlCode
     */
    public Smb2IoctlResponse ( Configuration config, byte[] outputBuffer, int ctlCode ) {
        super(config);
        this.outputBuffer = outputBuffer;
        this.ctlCode = ctlCode;
    }


    /**
     * @return the ctlCode
     */
    public int getCtlCode () {
        return this.ctlCode;
    }


    /**
     * @return the ioctlFlags
     */
    public int getIoctlFlags () {
        return this.ioctlFlags;
    }


    /**
     * @return the fileId
     */
    public byte[] getFileId () {
        return this.fileId;
    }


    /**
     * @return the outputData
     */
    public Decodable getOutputData () {
        return this.outputData;
    }


    /**
     * @return the outputLength
     */
    public int getOutputLength () {
        return this.outputLength;
    }


    /**
     * @return the inputData
     */
    public Decodable getInputData () {
        return this.inputData;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#writeBytesWireFormat(byte[], int)
     */
    @Override
    protected int writeBytesWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#isErrorResponseStatus()
     */
    @Override
    protected boolean isErrorResponseStatus () {
        int status = getStatus();
        return status != NtStatus.NT_STATUS_INVALID_PARAMETER
                && ! ( status == NtStatus.NT_STATUS_INVALID_PARAMETER
                        && ( this.ctlCode == Smb2IoctlRequest.FSCTL_SRV_COPYCHUNK || this.ctlCode == Smb2IoctlRequest.FSCTL_SRV_COPYCHUNK_WRITE ) )
                && ! ( status == NtStatus.NT_STATUS_BUFFER_OVERFLOW && ( this.ctlCode == Smb2IoctlRequest.FSCTL_PIPE_TRANSCEIVE
                        || this.ctlCode == Smb2IoctlRequest.FSCTL_PIPE_PEEK || this.ctlCode == Smb2IoctlRequest.FSCTL_DFS_GET_REFERRALS ) )
                && super.isErrorResponseStatus();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#readBytesWireFormat(byte[], int)
     */
    @Override
    protected int readBytesWireFormat ( byte[] buffer, int bufferIndex ) throws SMBProtocolDecodingException {
        int start = bufferIndex;
        int structureSize = SMBUtil.readInt2(buffer, bufferIndex);
        if ( structureSize == 9 ) {
            return super.readErrorResponse(buffer, bufferIndex);
        }
        else if ( structureSize != 49 ) {
            throw new SMBProtocolDecodingException("Expected structureSize = 49");
        }
        bufferIndex += 4;
        this.ctlCode = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        this.fileId = new byte[16];
        System.arraycopy(buffer, bufferIndex, this.fileId, 0, 16);
        bufferIndex += 16;

        int inputOffset = SMBUtil.readInt4(buffer, bufferIndex) + getHeaderStart();
        bufferIndex += 4;

        int inputCount = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        int outputOffset = SMBUtil.readInt4(buffer, bufferIndex) + getHeaderStart();
        bufferIndex += 4;

        int outputCount = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        this.ioctlFlags = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        bufferIndex += 4; // Reserved2

        this.inputData = createInputDecodable();
        this.outputData = this.outputBuffer == null ? createOutputDecodable() : null;

        if ( this.inputData != null ) {
            this.inputData.decode(buffer, inputOffset, inputCount);
        }
        bufferIndex = Math.max(inputOffset + inputCount, bufferIndex);

        if ( this.outputBuffer != null ) {
            if ( outputCount > this.outputBuffer.length ) {
                throw new SMBProtocolDecodingException("Output length exceeds buffer size");
            }
            System.arraycopy(buffer, outputOffset, this.outputBuffer, 0, outputCount);
        }
        else if ( this.outputData != null ) {
            this.outputData.decode(buffer, outputOffset, outputCount);
        }
        this.outputLength = outputCount;
        bufferIndex = Math.max(outputOffset + outputCount, bufferIndex);
        return bufferIndex - start;
    }


    /**
     * @return
     */
    protected Decodable createOutputDecodable () {
        switch ( this.ctlCode ) {
        case Smb2IoctlRequest.FSCTL_DFS_GET_REFERRALS:
            return new DfsReferralResponseBuffer();
        case Smb2IoctlRequest.FSCTL_SRV_REQUEST_RESUME_KEY:
            return new SrvRequestResumeKeyResponse();
        case Smb2IoctlRequest.FSCTL_SRV_COPYCHUNK:
        case Smb2IoctlRequest.FSCTL_SRV_COPYCHUNK_WRITE:
            return new SrvCopyChunkCopyResponse();
        case Smb2IoctlRequest.FSCTL_VALIDATE_NEGOTIATE_INFO:
            return new ValidateNegotiateInfoResponse();
        case Smb2IoctlRequest.FSCTL_PIPE_PEEK:
            return new SrvPipePeekResponse();
        }
        return null;
    }


    /**
     * @return
     */
    protected Decodable createInputDecodable () {
        return null;
    }


    /**
     * @param responseType
     * @return decoded data
     * @throws SmbException
     */
    @SuppressWarnings ( "unchecked" )
    public <T extends Decodable> T getOutputData ( Class<T> responseType ) throws SmbException {

        Decodable out = getOutputData();

        if ( out == null ) {
            throw new SmbException("Failed to decode output data");
        }

        if ( !responseType.isAssignableFrom(out.getClass()) ) {
            throw new SmbException("Incompatible response data " + out.getClass());
        }
        return (T) out;
    }

}
