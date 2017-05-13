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


/**
 *
 */
public class Trans2GetDfsReferral extends SmbComTransaction {

    private int maxReferralLevel = 3;


    /**
     * 
     * @param config
     * @param filename
     */
    public Trans2GetDfsReferral ( Configuration config, String filename ) {
        super(config, SMB_COM_TRANSACTION2, TRANS2_GET_DFS_REFERRAL);
        this.path = filename;
        this.totalDataCount = 0;
        this.maxParameterCount = 0;
        this.maxDataCount = 4096;
        this.maxSetupCount = (byte) 0x00;
    }


    @Override
    public boolean isForceUnicode () {
        return true;
    }


    @Override
    protected int writeSetupWireFormat ( byte[] dst, int dstIndex ) {
        dst[ dstIndex++ ] = this.getSubCommand();
        dst[ dstIndex++ ] = (byte) 0x00;
        return 2;
    }


    @Override
    protected int writeParametersWireFormat ( byte[] dst, int dstIndex ) {
        int start = dstIndex;

        SMBUtil.writeInt2(this.maxReferralLevel, dst, dstIndex);
        dstIndex += 2;
        dstIndex += writeString(this.path, dst, dstIndex);

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
            "Trans2GetDfsReferral[" + super.toString() + ",maxReferralLevel=0x" + this.maxReferralLevel + ",filename=" + this.path + "]");
    }
}
