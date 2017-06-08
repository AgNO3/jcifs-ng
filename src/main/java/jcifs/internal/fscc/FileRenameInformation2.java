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
package jcifs.internal.fscc;


import java.nio.charset.StandardCharsets;

import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.util.SMBUtil;


/**
 * @author mbechler
 *
 */
public class FileRenameInformation2 implements FileInformation {

    private boolean replaceIfExists;
    private String fileName;


    /**
     * 
     */
    public FileRenameInformation2 () {}


    /**
     * 
     * @param name
     * @param replaceIfExists
     */
    public FileRenameInformation2 ( String name, boolean replaceIfExists ) {
        this.fileName = name;
        this.replaceIfExists = replaceIfExists;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Decodable#decode(byte[], int, int)
     */
    @Override
    public int decode ( byte[] buffer, int bufferIndex, int len ) throws SMBProtocolDecodingException {
        int start = bufferIndex;
        this.replaceIfExists = buffer[ bufferIndex ] != 0;
        bufferIndex += 8;
        bufferIndex += 8;

        int nameLen = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        byte[] nameBytes = new byte[nameLen];
        System.arraycopy(buffer, bufferIndex, nameBytes, 0, nameBytes.length);
        bufferIndex += nameLen;
        this.fileName = new String(nameBytes, StandardCharsets.UTF_16LE);
        return bufferIndex - start;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Encodable#encode(byte[], int)
     */
    @Override
    public int encode ( byte[] dst, int dstIndex ) {
        int start = dstIndex;
        dst[ dstIndex ] = (byte) ( this.replaceIfExists ? 1 : 0 );
        dstIndex += 8; // 7 Reserved
        dstIndex += 8; // RootDirectory = 0

        byte[] nameBytes = this.fileName.getBytes(StandardCharsets.UTF_16LE);

        SMBUtil.writeInt4(nameBytes.length, dst, dstIndex);
        dstIndex += 4;

        System.arraycopy(nameBytes, 0, dst, dstIndex, nameBytes.length);
        dstIndex += nameBytes.length;

        return dstIndex - start;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Encodable#size()
     */
    @Override
    public int size () {
        return 20 + 2 * this.fileName.length();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.fscc.FileInformation#getFileInformationLevel()
     */
    @Override
    public byte getFileInformationLevel () {
        return FileInformation.FILE_RENAME_INFO;
    }

}
