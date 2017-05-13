/* jcifs smb client library in Java
 * Copyright (C) 2005  "Michael B. Allen" <jcifs at samba dot org>
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

package jcifs.internal.smb1.trans.nt;


import jcifs.Configuration;
import jcifs.internal.util.SMBUtil;
import jcifs.util.Hexdump;


/**
 * 
 */
public class NtTransQuerySecurityDesc extends SmbComNtTransaction {

    int fid;
    int securityInformation;


    /**
     * 
     * @param config
     * @param fid
     * @param securityInformation
     */
    public NtTransQuerySecurityDesc ( Configuration config, int fid, int securityInformation ) {
        super(config, NT_TRANSACT_QUERY_SECURITY_DESC);
        this.fid = fid;
        this.securityInformation = securityInformation;
        this.setupCount = 0;
        this.totalDataCount = 0;
        this.maxParameterCount = 4;
        this.maxDataCount = 65536;
        this.maxSetupCount = (byte) 0x00;
    }


    @Override
    public int getPadding () {
        return 4;
    }


    @Override
    protected int writeSetupWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    protected int writeParametersWireFormat ( byte[] dst, int dstIndex ) {
        int start = dstIndex;

        SMBUtil.writeInt2(this.fid, dst, dstIndex);
        dstIndex += 2;
        dst[ dstIndex++ ] = (byte) 0x00; // Reserved
        dst[ dstIndex++ ] = (byte) 0x00; // Reserved
        SMBUtil.writeInt4(this.securityInformation, dst, dstIndex);
        dstIndex += 4;
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
            "NtTransQuerySecurityDesc[" + super.toString() + ",fid=0x" + Hexdump.toHexString(this.fid, 4) + ",securityInformation=0x"
                    + Hexdump.toHexString(this.securityInformation, 8) + "]");
    }
}
