/* jcifs smb client library in Java
 * Copyright (C) 2000  "Michael B. Allen" <jcifs at samba dot org>
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

package jcifs.internal.smb1.com;


import jcifs.Configuration;
import jcifs.internal.SmbBasicFileInfo;
import jcifs.internal.smb1.AndXServerMessageBlock;
import jcifs.internal.util.SMBUtil;


/**
 * 
 */
public class SmbComOpenAndXResponse extends AndXServerMessageBlock implements SmbBasicFileInfo {

    private int fid, fileAttributes, fileDataSize, grantedAccess, fileType, deviceState, action, serverFid;
    private long lastWriteTime;


    /**
     * 
     * @param config
     */
    public SmbComOpenAndXResponse ( Configuration config ) {
        super(config);
    }


    /**
     * @param config
     * @param andxResp
     */
    public SmbComOpenAndXResponse ( Configuration config, SmbComSeekResponse andxResp ) {
        super(config, andxResp);
    }


    /**
     * @return the fid
     */
    public final int getFid () {
        return this.fid;
    }


    /**
     * @return the dataSize
     */
    public final int getDataSize () {
        return this.fileDataSize;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbBasicFileInfo#getSize()
     */
    @Override
    public long getSize () {
        return getDataSize();
    }


    /**
     * @return the grantedAccess
     */
    public final int getGrantedAccess () {
        return this.grantedAccess;
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
    public int getAttributes () {
        return getFileAttributes();
    }


    /**
     * @return the fileType
     */
    public final int getFileType () {
        return this.fileType;
    }


    /**
     * @return the deviceState
     */
    public final int getDeviceState () {
        return this.deviceState;
    }


    /**
     * @return the action
     */
    public final int getAction () {
        return this.action;
    }


    /**
     * @return the serverFid
     */
    public final int getServerFid () {
        return this.serverFid;
    }


    /**
     * @return the lastWriteTime
     */
    @Override
    public final long getLastWriteTime () {
        return this.lastWriteTime;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbBasicFileInfo#getCreateTime()
     */
    @Override
    public long getCreateTime () {
        return 0;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbBasicFileInfo#getLastAccessTime()
     */
    @Override
    public long getLastAccessTime () {
        return 0;
    }


    @Override
    protected int writeParameterWordsWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    protected int writeBytesWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    protected int readParameterWordsWireFormat ( byte[] buffer, int bufferIndex ) {
        int start = bufferIndex;

        this.fid = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.fileAttributes = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.lastWriteTime = SMBUtil.readUTime(buffer, bufferIndex);
        bufferIndex += 4;
        this.fileDataSize = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.grantedAccess = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.fileType = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.deviceState = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.action = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.serverFid = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 6;

        return bufferIndex - start;
    }


    @Override
    protected int readBytesWireFormat ( byte[] buffer, int bufferIndex ) {
        return 0;
    }


    @Override
    public String toString () {
        return new String(
            "SmbComOpenAndXResponse[" + super.toString() + ",fid=" + this.fid + ",fileAttributes=" + this.fileAttributes + ",lastWriteTime="
                    + this.lastWriteTime + ",dataSize=" + this.fileDataSize + ",grantedAccess=" + this.grantedAccess + ",fileType=" + this.fileType
                    + ",deviceState=" + this.deviceState + ",action=" + this.action + ",serverFid=" + this.serverFid + "]");
    }
}
