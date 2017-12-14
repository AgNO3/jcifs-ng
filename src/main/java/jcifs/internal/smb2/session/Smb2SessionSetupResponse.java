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
package jcifs.internal.smb2.session;


import jcifs.Configuration;
import jcifs.internal.CommonServerMessageBlockRequest;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.smb2.ServerMessageBlock2Response;
import jcifs.internal.util.SMBUtil;
import jcifs.smb.NtStatus;


/**
 * @author mbechler
 *
 */
public class Smb2SessionSetupResponse extends ServerMessageBlock2Response {

    /**
     * 
     */
    public static final int SMB2_SESSION_FLAGS_IS_GUEST = 0x1;

    /**
     * 
     */
    public static final int SMB2_SESSION_FLAGS_IS_NULL = 0x2;

    /**
     * 
     */
    public static final int SMB2_SESSION_FLAG_ENCRYPT_DATA = 0x4;

    private int sessionFlags;
    private byte[] blob;


    /**
     * @param config
     */
    public Smb2SessionSetupResponse ( Configuration config ) {
        super(config);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2Response#prepare(jcifs.internal.CommonServerMessageBlockRequest)
     */
    @Override
    public void prepare ( CommonServerMessageBlockRequest next ) {
        if ( isReceived() ) {
            next.setSessionId(getSessionId());
        }
        super.prepare(next);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#isErrorResponseStatus()
     */
    @Override
    protected boolean isErrorResponseStatus () {
        return getStatus() != NtStatus.NT_STATUS_MORE_PROCESSING_REQUIRED && super.isErrorResponseStatus();
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
     * @throws Smb2ProtocolDecodingException
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#readBytesWireFormat(byte[], int)
     */
    @Override
    protected int readBytesWireFormat ( byte[] buffer, int bufferIndex ) throws SMBProtocolDecodingException {
        int start = bufferIndex;

        int structureSize = SMBUtil.readInt2(buffer, bufferIndex);
        if ( structureSize != 9 ) {
            throw new SMBProtocolDecodingException("Structure size != 9");
        }

        this.sessionFlags = SMBUtil.readInt2(buffer, bufferIndex + 2);
        bufferIndex += 4;

        int securityBufferOffset = SMBUtil.readInt2(buffer, bufferIndex);
        int securityBufferLength = SMBUtil.readInt2(buffer, bufferIndex + 2);
        bufferIndex += 4;

        int pad = bufferIndex - ( getHeaderStart() + securityBufferOffset );
        this.blob = new byte[securityBufferLength];
        System.arraycopy(buffer, getHeaderStart() + securityBufferOffset, this.blob, 0, securityBufferLength);
        bufferIndex += pad;
        bufferIndex += securityBufferLength;

        return bufferIndex - start;
    }


    /**
     * @return whether the session is either anonymous or a guest session
     */
    public boolean isLoggedInAsGuest () {
        return ( this.sessionFlags & ( SMB2_SESSION_FLAGS_IS_GUEST | SMB2_SESSION_FLAGS_IS_NULL ) ) != 0;
    }


    /**
     * @return the sessionFlags
     */
    public int getSessionFlags () {
        return this.sessionFlags;
    }


    /**
     * @return security blob
     */
    public byte[] getBlob () {
        return this.blob;
    }

}
