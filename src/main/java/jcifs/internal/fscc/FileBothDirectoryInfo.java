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


import java.util.Date;

import jcifs.Configuration;
import jcifs.Decodable;
import jcifs.SmbConstants;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.util.SMBUtil;
import jcifs.smb.FileEntry;
import jcifs.util.Strings;


/**
 * 
 */
public class FileBothDirectoryInfo implements FileEntry, Decodable {

    private int nextEntryOffset;
    private int fileIndex;
    private long creationTime;
    private long lastAccessTime;
    private long lastWriteTime;
    private long changeTime;
    private long endOfFile;
    private long allocationSize;
    private int extFileAttributes;
    private int eaSize;
    private String shortName;
    private String filename;
    private final Configuration config;
    private final boolean unicode;


    /**
     * @param config
     * @param unicode
     * 
     */
    public FileBothDirectoryInfo ( Configuration config, boolean unicode ) {
        this.config = config;
        this.unicode = unicode;
    }


    @Override
    public String getName () {
        return this.filename;
    }


    @Override
    public int getType () {
        return SmbConstants.TYPE_FILESYSTEM;
    }


    /**
     * @return the fileIndex
     */
    @Override
    public int getFileIndex () {
        return this.fileIndex;
    }


    /**
     * @return the filename
     */
    public String getFilename () {
        return this.filename;
    }


    @Override
    public int getAttributes () {
        return this.extFileAttributes;
    }


    @Override
    public long createTime () {
        return this.creationTime;
    }


    @Override
    public long lastModified () {
        return this.lastWriteTime;
    }


    @Override
    public long lastAccess () {
        return this.lastAccessTime;
    }


    @Override
    public long length () {
        return this.endOfFile;
    }


    /**
     * @return the nextEntryOffset
     */
    public int getNextEntryOffset () {
        return this.nextEntryOffset;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Decodable#decode(byte[], int, int)
     */
    @Override
    public int decode ( byte[] buffer, int bufferIndex, int len ) throws SMBProtocolDecodingException {
        int start = bufferIndex;
        this.nextEntryOffset = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.fileIndex = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.creationTime = SMBUtil.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        this.lastAccessTime = SMBUtil.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        this.lastWriteTime = SMBUtil.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        this.changeTime = SMBUtil.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        this.endOfFile = SMBUtil.readInt8(buffer, bufferIndex);
        bufferIndex += 8;
        this.allocationSize = SMBUtil.readInt8(buffer, bufferIndex);
        bufferIndex += 8;
        this.extFileAttributes = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        int fileNameLength = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.eaSize = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        int shortNameLength = buffer[ bufferIndex ] & 0xFF;
        bufferIndex += 2;

        this.shortName = Strings.fromUNIBytes(buffer, bufferIndex, shortNameLength);
        bufferIndex += 24;

        String str;
        if ( this.unicode ) {
            if ( fileNameLength > 0 && buffer[ bufferIndex + fileNameLength - 1 ] == '\0' && buffer[ bufferIndex + fileNameLength - 2 ] == '\0' ) {
                fileNameLength -= 2;
            }
            str = Strings.fromUNIBytes(buffer, bufferIndex, fileNameLength);
        }
        else {
            if ( fileNameLength > 0 && buffer[ bufferIndex + fileNameLength - 1 ] == '\0' ) {
                fileNameLength -= 1;
            }
            str = Strings.fromOEMBytes(buffer, bufferIndex, fileNameLength, this.config);
        }
        this.filename = str;
        bufferIndex += fileNameLength;

        return start - bufferIndex;
    }


    @Override
    public String toString () {
        return new String(
            "SmbFindFileBothDirectoryInfo[" + "nextEntryOffset=" + this.nextEntryOffset + ",fileIndex=" + this.fileIndex + ",creationTime="
                    + new Date(this.creationTime) + ",lastAccessTime=" + new Date(this.lastAccessTime) + ",lastWriteTime="
                    + new Date(this.lastWriteTime) + ",changeTime=" + new Date(this.changeTime) + ",endOfFile=" + this.endOfFile + ",allocationSize="
                    + this.allocationSize + ",extFileAttributes=" + this.extFileAttributes + ",eaSize=" + this.eaSize + ",shortName=" + this.shortName
                    + ",filename=" + this.filename + "]");
    }

}