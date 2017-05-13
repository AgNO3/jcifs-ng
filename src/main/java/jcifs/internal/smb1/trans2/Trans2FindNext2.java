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
import jcifs.internal.smb1.trans.SmbComTransaction;
import jcifs.internal.util.SMBUtil;
import jcifs.util.Hexdump;


/**
 * 
 */
public class Trans2FindNext2 extends SmbComTransaction {

    private int sid, informationLevel, resumeKey, tflags;
    private String filename;
    private long maxItems;


    /**
     * 
     * @param config
     * @param sid
     * @param resumeKey
     * @param filename
     * @param batchCount
     * @param batchSize
     */
    public Trans2FindNext2 ( Configuration config, int sid, int resumeKey, String filename, int batchCount, int batchSize ) {
        super(config, SMB_COM_TRANSACTION2, TRANS2_FIND_NEXT2);
        this.sid = sid;
        this.resumeKey = resumeKey;
        this.filename = filename;
        this.informationLevel = Trans2FindFirst2.SMB_FILE_BOTH_DIRECTORY_INFO;
        this.tflags = 0x00;
        this.maxParameterCount = 8;
        this.maxItems = batchCount;
        this.maxDataCount = batchSize;
        this.maxSetupCount = 0;
    }


    @Override
    public void reset ( int rk, String lastName ) {
        super.reset();
        this.resumeKey = rk;
        this.filename = lastName;
        this.flags2 = 0;
    }


    @Override
    protected int writeSetupWireFormat ( byte[] dst, int dstIndex ) {
        dst[ dstIndex++ ] = getSubCommand();
        dst[ dstIndex++ ] = (byte) 0x00;
        return 2;
    }


    @Override
    protected int writeParametersWireFormat ( byte[] dst, int dstIndex ) {
        int start = dstIndex;

        SMBUtil.writeInt2(this.sid, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt2(this.maxItems, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt2(this.informationLevel, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt4(this.resumeKey, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt2(this.tflags, dst, dstIndex);
        dstIndex += 2;
        dstIndex += writeString(this.filename, dst, dstIndex);

        return dstIndex - start;
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
        return 0;
    }


    @Override
    public String toString () {
        return new String(
            "Trans2FindNext2[" + super.toString() + ",sid=" + this.sid + ",searchCount=" + getConfig().getListSize() + ",informationLevel=0x"
                    + Hexdump.toHexString(this.informationLevel, 3) + ",resumeKey=0x" + Hexdump.toHexString(this.resumeKey, 4) + ",flags=0x"
                    + Hexdump.toHexString(this.tflags, 2) + ",filename=" + this.filename + "]");
    }
}
