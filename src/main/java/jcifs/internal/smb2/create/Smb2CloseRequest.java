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
package jcifs.internal.smb2.create;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.internal.smb2.RequestWithFileId;
import jcifs.internal.smb2.ServerMessageBlock2Request;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.util.SMBUtil;
import jcifs.util.Hexdump;


/**
 * @author mbechler
 *
 */
public class Smb2CloseRequest extends ServerMessageBlock2Request<Smb2CloseResponse> implements RequestWithFileId {

    private static final Logger log = LoggerFactory.getLogger(Smb2CloseRequest.class);

    private byte[] fileId;
    private final String fileName;
    private int closeFlags;


    /**
     * @param config
     * @param fileId
     * @param fileName
     */
    public Smb2CloseRequest ( Configuration config, byte[] fileId, String fileName ) {
        super(config, SMB2_CLOSE);
        this.fileId = fileId;
        this.fileName = fileName;
    }


    /**
     * 
     * @param config
     * @param fileId
     */
    public Smb2CloseRequest ( Configuration config, byte[] fileId ) {
        this(config, fileId, "");
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
     * @param config
     * @param fileName
     */
    public Smb2CloseRequest ( Configuration config, String fileName ) {
        this(config, Smb2Constants.UNSPECIFIED_FILEID, fileName);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#createResponse(jcifs.Configuration,
     *      jcifs.internal.smb2.ServerMessageBlock2)
     */
    @Override
    protected Smb2CloseResponse createResponse ( CIFSContext tc, ServerMessageBlock2Request<Smb2CloseResponse> req ) {
        return new Smb2CloseResponse(tc.getConfig(), this.fileId, this.fileName);
    }


    /**
     * @param flags
     *            the flags to set
     */
    public void setCloseFlags ( int flags ) {
        this.closeFlags = flags;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockRequest#size()
     */
    @Override
    public int size () {
        return size8(Smb2Constants.SMB2_HEADER_LENGTH + 24);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#writeBytesWireFormat(byte[], int)
     */
    @Override
    protected int writeBytesWireFormat ( byte[] dst, int dstIndex ) {
        int start = dstIndex;
        SMBUtil.writeInt2(24, dst, dstIndex);
        SMBUtil.writeInt2(this.closeFlags, dst, dstIndex + 2);
        dstIndex += 4;
        dstIndex += 4; // Reserved
        System.arraycopy(this.fileId, 0, dst, dstIndex, 16);
        dstIndex += 16;

        if ( log.isDebugEnabled() ) {
            log.debug(String.format("Closing %s (%s)", Hexdump.toHexString(this.fileId), this.fileName));
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
