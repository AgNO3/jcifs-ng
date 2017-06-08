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


import java.util.ArrayList;
import java.util.List;

import jcifs.Configuration;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.fscc.FileBothDirectoryInfo;
import jcifs.internal.smb2.ServerMessageBlock2Response;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.util.SMBUtil;
import jcifs.smb.FileEntry;


/**
 * @author mbechler
 *
 */
public class Smb2QueryDirectoryResponse extends ServerMessageBlock2Response {

    /**
     * 
     */
    public static final int OVERHEAD = Smb2Constants.SMB2_HEADER_LENGTH + 8;

    private final byte expectInfoClass;
    private FileEntry[] results;


    /**
     * @param config
     * @param expectInfoClass
     */
    public Smb2QueryDirectoryResponse ( Configuration config, byte expectInfoClass ) {
        super(config);
        this.expectInfoClass = expectInfoClass;
    }


    /**
     * @return the fileInformation
     */
    public FileEntry[] getResults () {
        return this.results;
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

        if ( structureSize != 9 ) {
            throw new SMBProtocolDecodingException("Expected structureSize = 9");
        }

        int bufferOffset = SMBUtil.readInt2(buffer, bufferIndex + 2) + getHeaderStart();
        bufferIndex += 4;
        int bufferLength = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        // bufferIndex = bufferOffset;

        List<FileEntry> infos = new ArrayList<>();
        do {
            FileBothDirectoryInfo cur = createFileInfo();
            if ( cur == null ) {
                break;
            }
            cur.decode(buffer, bufferIndex, bufferLength);
            infos.add(cur);
            int nextEntryOffset = cur.getNextEntryOffset();
            if ( nextEntryOffset > 0 ) {
                bufferIndex += nextEntryOffset;
            }
            else {
                break;
            }
        }
        while ( bufferIndex < bufferOffset + bufferLength );
        this.results = infos.toArray(new FileEntry[infos.size()]);
        return bufferIndex - start;
    }


    private FileBothDirectoryInfo createFileInfo () {
        if ( this.expectInfoClass == Smb2QueryDirectoryRequest.FILE_BOTH_DIRECTORY_INFO ) {
            return new FileBothDirectoryInfo(getConfig(), true);
        }
        return null;
    }

}
