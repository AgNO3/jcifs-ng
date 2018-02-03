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

import jcifs.Configuration;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.SmbBasicFileInfo;
import jcifs.internal.smb2.ServerMessageBlock2Response;
import jcifs.internal.util.SMBUtil;
import jcifs.util.Hexdump;


/**
 * @author mbechler
 *
 */
public class Smb2CloseResponse extends ServerMessageBlock2Response implements SmbBasicFileInfo {

    private static final Logger log = LoggerFactory.getLogger(Smb2CloseResponse.class);

    /**
     * 
     */
    public static final int SMB2_CLOSE_FLAG_POSTQUERY_ATTIB = 0x1;

    private final byte[] fileId;
    private final String fileName;
    private int closeFlags;
    private long creationTime;
    private long lastAccessTime;
    private long lastWriteTime;
    private long changeTime;
    private long allocationSize;
    private long endOfFile;
    private int fileAttributes;


    /**
     * @param config
     * @param fileId
     * @param fileName
     */
    public Smb2CloseResponse ( Configuration config, byte[] fileId, String fileName ) {
        super(config);
        this.fileId = fileId;
        this.fileName = fileName;
    }


    /**
     * @return the closeFlags
     */
    public final int getCloseFlags () {
        return this.closeFlags;
    }


    /**
     * @return the creationTime
     */
    public final long getCreationTime () {
        return this.creationTime;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbBasicFileInfo#getCreateTime()
     */
    @Override
    public final long getCreateTime () {
        return getCreationTime();
    }


    /**
     * @return the lastAccessTime
     */
    @Override
    public final long getLastAccessTime () {
        return this.lastAccessTime;
    }


    /**
     * @return the lastWriteTime
     */
    @Override
    public final long getLastWriteTime () {
        return this.lastWriteTime;
    }


    /**
     * @return the changeTime
     */
    public final long getChangeTime () {
        return this.changeTime;
    }


    /**
     * @return the allocationSize
     */
    public final long getAllocationSize () {
        return this.allocationSize;
    }


    /**
     * @return the endOfFile
     */
    public final long getEndOfFile () {
        return this.endOfFile;
    }


    /**
     * @return the fileId
     */
    public byte[] getFileId () {
        return this.fileId;
    }


    /**
     * @return the fileName
     */
    public String getFileName () {
        return this.fileName;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbBasicFileInfo#getSize()
     */
    @Override
    public long getSize () {
        return getEndOfFile();
    }


    /**
     * @return the fileAttributes
     */
    public int getFileAttributes () {
        return this.fileAttributes;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbBasicFileInfo#getAttributes()
     */
    @Override
    public int getAttributes () {
        return getFileAttributes();
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
     * @see jcifs.internal.smb2.ServerMessageBlock2#readBytesWireFormat(byte[], int)
     */
    @Override
    protected int readBytesWireFormat ( byte[] buffer, int bufferIndex ) throws SMBProtocolDecodingException {
        int start = bufferIndex;
        int structureSize = SMBUtil.readInt2(buffer, bufferIndex);
        if ( structureSize != 60 ) {
            throw new SMBProtocolDecodingException("Expected structureSize = 60");
        }
        this.closeFlags = SMBUtil.readInt2(buffer, bufferIndex + 2);
        bufferIndex += 4;
        bufferIndex += 4; // Reserved
        this.creationTime = SMBUtil.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        this.lastAccessTime = SMBUtil.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        this.lastWriteTime = SMBUtil.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        this.changeTime = SMBUtil.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        this.allocationSize = SMBUtil.readInt8(buffer, bufferIndex);
        bufferIndex += 8;
        this.endOfFile = SMBUtil.readInt8(buffer, bufferIndex);
        bufferIndex += 8;
        this.fileAttributes = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        if ( log.isDebugEnabled() ) {
            log.debug(String.format("Closed %s (%s)", Hexdump.toHexString(this.fileId), this.fileName));
        }

        return bufferIndex - start;
    }

}
