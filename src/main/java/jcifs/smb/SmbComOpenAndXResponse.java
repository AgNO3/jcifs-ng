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

package jcifs.smb;


import jcifs.Configuration;


class SmbComOpenAndXResponse extends AndXServerMessageBlock {

    int fid, fileAttributes, dataSize, grantedAccess, fileType, deviceState, action, serverFid;
    long lastWriteTime;


    SmbComOpenAndXResponse ( Configuration config ) {
        super(config);
    }


    @Override
    int writeParameterWordsWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    int writeBytesWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    int readParameterWordsWireFormat ( byte[] buffer, int bufferIndex ) {
        int start = bufferIndex;

        this.fid = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.fileAttributes = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.lastWriteTime = SMBUtil.readUTime(buffer, bufferIndex);
        bufferIndex += 4;
        this.dataSize = SMBUtil.readInt4(buffer, bufferIndex);
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
    int readBytesWireFormat ( byte[] buffer, int bufferIndex ) {
        return 0;
    }


    @Override
    public String toString () {
        return new String(
            "SmbComOpenAndXResponse[" + super.toString() + ",fid=" + this.fid + ",fileAttributes=" + this.fileAttributes + ",lastWriteTime="
                    + this.lastWriteTime + ",dataSize=" + this.dataSize + ",grantedAccess=" + this.grantedAccess + ",fileType=" + this.fileType
                    + ",deviceState=" + this.deviceState + ",action=" + this.action + ",serverFid=" + this.serverFid + "]");
    }
}
