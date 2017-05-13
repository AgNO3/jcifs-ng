/**
 * © 2017 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: May 13, 2017 by mbechler
 */
package jcifs.internal.smb1.trans2;


import java.util.Date;

import jcifs.SmbConstants;
import jcifs.smb.FileEntry;


/**
 * 
 */
public class SmbFindFileBothDirectoryInfo implements FileEntry {

    int nextEntryOffset;
    int fileIndex;
    long creationTime;
    long lastAccessTime;
    long lastWriteTime;
    long changeTime;
    long endOfFile;
    long allocationSize;
    int extFileAttributes;
    int fileNameLength;
    int eaSize;
    int shortNameLength;
    String shortName;
    String filename;


    @Override
    public String getName () {
        return this.filename;
    }


    @Override
    public int getType () {
        return SmbConstants.TYPE_FILESYSTEM;
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


    @Override
    public String toString () {
        return new String(
            "SmbFindFileBothDirectoryInfo[" + "nextEntryOffset=" + this.nextEntryOffset + ",fileIndex=" + this.fileIndex + ",creationTime="
                    + new Date(this.creationTime) + ",lastAccessTime=" + new Date(this.lastAccessTime) + ",lastWriteTime="
                    + new Date(this.lastWriteTime) + ",changeTime=" + new Date(this.changeTime) + ",endOfFile=" + this.endOfFile + ",allocationSize="
                    + this.allocationSize + ",extFileAttributes=" + this.extFileAttributes + ",fileNameLength=" + this.fileNameLength + ",eaSize="
                    + this.eaSize + ",shortNameLength=" + this.shortNameLength + ",shortName=" + this.shortName + ",filename=" + this.filename + "]");
    }
}