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

package jcifs.internal.smb1.trans2;


import jcifs.Configuration;
import jcifs.internal.SmbBasicFileInfo;
import jcifs.internal.smb1.trans.SmbComTransaction;
import jcifs.internal.smb1.trans.SmbComTransactionResponse;
import jcifs.internal.util.SMBUtil;


/**
 * 
 */
public class Trans2QueryPathInformationResponse extends SmbComTransactionResponse {

    // information levels
    /**
     * 
     */
    public static final int SMB_QUERY_FILE_BASIC_INFO = 0x101;
    /**
     * 
     */
    public static final int SMB_QUERY_FILE_STANDARD_INFO = 0x102;

    private int informationLevel;

    private SmbBasicFileInfo info;


    /**
     * 
     * @param config
     * @param informationLevel
     */
    public Trans2QueryPathInformationResponse ( Configuration config, int informationLevel ) {
        super(config);
        this.informationLevel = informationLevel;
        this.setSubCommand(SmbComTransaction.TRANS2_QUERY_PATH_INFORMATION);
    }


    /**
     * @return the info
     */
    public final SmbBasicFileInfo getInfo () {
        return this.info;
    }


    @Override
    protected int writeSetupWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    protected int writeParametersWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    protected int writeDataWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    protected int readSetupWireFormat ( byte[] buffer, int bufferIndex, int len ) {
        return 0;
    }


    @Override
    protected int readParametersWireFormat ( byte[] buffer, int bufferIndex, int len ) {
        // observed two zero bytes here with at least win98
        return 2;
    }


    @Override
    protected int readDataWireFormat ( byte[] buffer, int bufferIndex, int len ) {
        switch ( this.informationLevel ) {
        case SMB_QUERY_FILE_BASIC_INFO:
            return readSmbQueryFileBasicInfoWireFormat(buffer, bufferIndex);
        case SMB_QUERY_FILE_STANDARD_INFO:
            return readSmbQueryFileStandardInfoWireFormat(buffer, bufferIndex);
        default:
            return 0;
        }
    }


    int readSmbQueryFileStandardInfoWireFormat ( byte[] buffer, int bufferIndex ) {
        int start = bufferIndex;
        SmbQueryFileStandardInfo inf = new SmbQueryFileStandardInfo();
        inf.allocationSize = SMBUtil.readInt8(buffer, bufferIndex);
        bufferIndex += 8;
        inf.endOfFile = SMBUtil.readInt8(buffer, bufferIndex);
        bufferIndex += 8;
        inf.numberOfLinks = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        inf.deletePending = ( buffer[ bufferIndex++ ] & 0xFF ) > 0;
        inf.directory = ( buffer[ bufferIndex++ ] & 0xFF ) > 0;
        this.info = inf;

        return bufferIndex - start;
    }


    int readSmbQueryFileBasicInfoWireFormat ( byte[] buffer, int bufferIndex ) {
        int start = bufferIndex;

        SmbQueryFileBasicInfo inf = new SmbQueryFileBasicInfo();
        inf.createTime = SMBUtil.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        inf.lastAccessTime = SMBUtil.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        inf.lastWriteTime = SMBUtil.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        inf.changeTime = SMBUtil.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        inf.attributes = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.info = inf;

        return bufferIndex - start;
    }


    @Override
    public String toString () {
        return new String("Trans2QueryPathInformationResponse[" + super.toString() + "]");
    }
}
