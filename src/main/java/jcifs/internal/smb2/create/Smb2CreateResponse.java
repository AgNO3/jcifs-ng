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


import java.util.LinkedList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.Configuration;
import jcifs.internal.CommonServerMessageBlockRequest;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.SmbBasicFileInfo;
import jcifs.internal.smb2.RequestWithFileId;
import jcifs.internal.smb2.ServerMessageBlock2Response;
import jcifs.internal.util.SMBUtil;
import jcifs.util.Hexdump;


/**
 * @author mbechler
 *
 */
public class Smb2CreateResponse extends ServerMessageBlock2Response implements SmbBasicFileInfo {

    private static final Logger log = LoggerFactory.getLogger(Smb2CreateResponse.class);

    private byte oplockLevel;
    private byte openFlags;
    private int createAction;
    private long creationTime;
    private long lastAccessTime;
    private long lastWriteTime;
    private long changeTime;
    private long allocationSize;
    private long endOfFile;
    private int fileAttributes;
    private byte[] fileId = new byte[16];
    private CreateContextResponse[] createContexts;
    private final String fileName;


    /**
     * @param config
     * @param name
     */
    public Smb2CreateResponse ( Configuration config, String name ) {
        super(config);
        this.fileName = name;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2Response#prepare(jcifs.internal.CommonServerMessageBlockRequest)
     */
    @Override
    public void prepare ( CommonServerMessageBlockRequest next ) {
        if ( isReceived() && ( next instanceof RequestWithFileId ) ) {
            ( (RequestWithFileId) next ).setFileId(this.fileId);
        }
        super.prepare(next);
    }


    /**
     * @return the oplockLevel
     */
    public final byte getOplockLevel () {
        return this.oplockLevel;
    }


    /**
     * @return the flags
     */
    public final byte getOpenFlags () {
        return this.openFlags;
    }


    /**
     * @return the createAction
     */
    public final int getCreateAction () {
        return this.createAction;
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
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbBasicFileInfo#getSize()
     */
    @Override
    public final long getSize () {
        return getEndOfFile();
    }


    /**
     * @return the fileAttributes
     */
    public final int getFileAttributes () {
        return this.fileAttributes;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbBasicFileInfo#getAttributes()
     */
    @Override
    public final int getAttributes () {
        return getFileAttributes();
    }


    /**
     * @return the fileId
     */
    public final byte[] getFileId () {
        return this.fileId;
    }


    /**
     * @return the fileName
     */
    public final String getFileName () {
        return this.fileName;
    }


    /**
     * @return the createContexts
     */
    public CreateContextResponse[] getCreateContexts () {
        return this.createContexts;
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

        if ( structureSize != 89 ) {
            throw new SMBProtocolDecodingException("Structure size is not 89");
        }

        this.oplockLevel = buffer[ bufferIndex + 2 ];
        this.openFlags = buffer[ bufferIndex + 3 ];
        bufferIndex += 4;

        this.createAction = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

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
        bufferIndex += 4; // Reserved2

        System.arraycopy(buffer, bufferIndex, this.fileId, 0, 16);
        bufferIndex += 16;

        int createContextOffset = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        int createContextLength = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        if ( createContextOffset > 0 && createContextLength > 0 ) {
            List<CreateContextResponse> contexts = new LinkedList<>();
            int createContextStart = getHeaderStart() + createContextOffset;
            int next = 0;
            do {
                int cci = createContextStart;
                next = SMBUtil.readInt4(buffer, cci);
                cci += 4;

                int nameOffset = SMBUtil.readInt2(buffer, cci);
                int nameLength = SMBUtil.readInt2(buffer, cci + 2);
                cci += 4;

                int dataOffset = SMBUtil.readInt2(buffer, cci + 2);
                cci += 4;
                int dataLength = SMBUtil.readInt4(buffer, cci);
                cci += 4;

                byte[] nameBytes = new byte[nameLength];
                System.arraycopy(buffer, createContextStart + nameOffset, nameBytes, 0, nameBytes.length);
                cci = Math.max(cci, createContextStart + nameOffset + nameLength);

                CreateContextResponse cc = createContext(nameBytes);
                if ( cc != null ) {
                    cc.decode(buffer, createContextStart + dataOffset, dataLength);
                    contexts.add(cc);
                }

                cci = Math.max(cci, createContextStart + dataOffset + dataLength);

                if ( next > 0 ) {
                    createContextStart += next;
                }
                bufferIndex = Math.max(bufferIndex, cci);
            }
            while ( next > 0 );
            this.createContexts = contexts.toArray(new CreateContextResponse[0]);
        }

        if ( log.isDebugEnabled() ) {
            log.debug("Opened " + this.fileName + ": " + Hexdump.toHexString(this.fileId));
        }

        return bufferIndex - start;
    }


    /**
     * @param nameBytes
     * @return
     */
    private static CreateContextResponse createContext ( byte[] nameBytes ) {
        return null;
    }

}
