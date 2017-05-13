/**
 * © 2017 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: May 13, 2017 by mbechler
 */
package jcifs.internal.smb1.trans2;

import jcifs.internal.SmbBasicFileInfo;

class SmbQueryFileStandardInfo implements SmbBasicFileInfo {

    long allocationSize;
    long endOfFile;
    int numberOfLinks;
    boolean deletePending;
    boolean directory;


    @Override
    public int getAttributes () {
        return 0;
    }


    @Override
    public long getCreateTime () {
        return 0L;
    }


    @Override
    public long getLastWriteTime () {
        return 0L;
    }


    @Override
    public long getLastAccessTime () {
        return 0L;
    }


    @Override
    public long getSize () {
        return this.endOfFile;
    }


    @Override
    public String toString () {
        return new String(
            "SmbQueryInfoStandard[" + "allocationSize=" + this.allocationSize + ",endOfFile=" + this.endOfFile + ",numberOfLinks="
                    + this.numberOfLinks + ",deletePending=" + this.deletePending + ",directory=" + this.directory + "]");
    }
}