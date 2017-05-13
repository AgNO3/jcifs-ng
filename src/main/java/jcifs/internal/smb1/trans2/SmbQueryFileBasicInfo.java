/**
 * © 2017 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: May 13, 2017 by mbechler
 */
package jcifs.internal.smb1.trans2;

import java.util.Date;

import jcifs.internal.SmbBasicFileInfo;
import jcifs.util.Hexdump;

class SmbQueryFileBasicInfo implements SmbBasicFileInfo {

    long createTime;
    long lastAccessTime;
    long lastWriteTime;
    long changeTime;
    int attributes;


    @Override
    public int getAttributes () {
        return this.attributes;
    }


    @Override
    public long getCreateTime () {
        return this.createTime;
    }


    @Override
    public long getLastWriteTime () {
        return this.lastWriteTime;
    }


    @Override
    public long getLastAccessTime () {
        return this.lastAccessTime;
    }


    @Override
    public long getSize () {
        return 0L;
    }


    @Override
    public String toString () {
        return new String(
            "SmbQueryFileBasicInfo[" + "createTime=" + new Date(this.createTime) + ",lastAccessTime=" + new Date(this.lastAccessTime)
                    + ",lastWriteTime=" + new Date(this.lastWriteTime) + ",changeTime=" + new Date(this.changeTime) + ",attributes=0x"
                    + Hexdump.toHexString(this.attributes, 4) + "]");
    }
}