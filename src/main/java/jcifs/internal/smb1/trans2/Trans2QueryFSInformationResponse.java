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
import jcifs.internal.AllocInfo;
import jcifs.internal.smb1.trans.SmbComTransaction;
import jcifs.internal.smb1.trans.SmbComTransactionResponse;
import jcifs.internal.util.SMBUtil;


/**
 * 
 */
public class Trans2QueryFSInformationResponse extends SmbComTransactionResponse {

    // information levels
    /**
     * 
     */
    public static final int SMB_INFO_ALLOCATION = 1;
    /**
     * 
     */
    public static final int SMB_QUERY_FS_SIZE_INFO = 0x103;
    /**
     * 
     */
    public static final int SMB_FS_FULL_SIZE_INFORMATION = 1007;

    private int informationLevel;
    private AllocInfo info;


    /**
     * 
     * @param config
     * @param informationLevel
     */
    public Trans2QueryFSInformationResponse ( Configuration config, int informationLevel ) {
        super(config);
        this.informationLevel = informationLevel;
        this.setCommand(SMB_COM_TRANSACTION2);
        this.setSubCommand(SmbComTransaction.TRANS2_QUERY_FS_INFORMATION);
    }


    /**
     * @return the informationLevel
     */
    public int getInformationLevel () {
        return this.informationLevel;
    }


    /**
     * @return the info
     */
    public AllocInfo getInfo () {
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
        return 0;
    }


    @Override
    protected int readDataWireFormat ( byte[] buffer, int bufferIndex, int len ) {
        switch ( this.informationLevel ) {
        case SMB_INFO_ALLOCATION:
            return readSmbInfoAllocationWireFormat(buffer, bufferIndex);
        case SMB_QUERY_FS_SIZE_INFO:
            return readSmbQueryFSSizeInfoWireFormat(buffer, bufferIndex);
        case SMB_FS_FULL_SIZE_INFORMATION:
            return readFsFullSizeInformationWireFormat(buffer, bufferIndex);
        default:
            return 0;
        }
    }


    int readSmbInfoAllocationWireFormat ( byte[] buffer, int bufferIndex ) {
        int start = bufferIndex;

        SmbInfoAllocation inf = new SmbInfoAllocation();

        bufferIndex += 4; // skip idFileSystem

        inf.sectPerAlloc = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        inf.alloc = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        inf.free = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        inf.bytesPerSect = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 4;

        this.info = inf;

        return bufferIndex - start;
    }


    int readSmbQueryFSSizeInfoWireFormat ( byte[] buffer, int bufferIndex ) {
        int start = bufferIndex;

        SmbInfoAllocation inf = new SmbInfoAllocation();

        inf.alloc = SMBUtil.readInt8(buffer, bufferIndex);
        bufferIndex += 8;

        inf.free = SMBUtil.readInt8(buffer, bufferIndex);
        bufferIndex += 8;

        inf.sectPerAlloc = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        inf.bytesPerSect = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        this.info = inf;

        return bufferIndex - start;
    }


    int readFsFullSizeInformationWireFormat ( byte[] buffer, int bufferIndex ) {
        int start = bufferIndex;

        SmbInfoAllocation inf = new SmbInfoAllocation();

        // Read total allocation units.
        inf.alloc = SMBUtil.readInt8(buffer, bufferIndex);
        bufferIndex += 8;

        // read caller available allocation units
        inf.free = SMBUtil.readInt8(buffer, bufferIndex);
        bufferIndex += 8;

        // skip actual free units
        bufferIndex += 8;

        inf.sectPerAlloc = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        inf.bytesPerSect = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        this.info = inf;

        return bufferIndex - start;
    }


    @Override
    public String toString () {
        return new String("Trans2QueryFSInformationResponse[" + super.toString() + "]");
    }
}
