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
import jcifs.util.Hexdump;


class Trans2QueryPathInformation extends SmbComTransaction {

    private int informationLevel;


    Trans2QueryPathInformation ( Configuration config, String filename, int informationLevel ) {
        super(config);
        this.path = filename;
        this.informationLevel = informationLevel;
        this.command = SMB_COM_TRANSACTION2;
        this.subCommand = TRANS2_QUERY_PATH_INFORMATION;
        this.totalDataCount = 0;
        this.maxParameterCount = 2;
        this.maxDataCount = 40;
        this.maxSetupCount = (byte) 0x00;
    }


    @Override
    int writeSetupWireFormat ( byte[] dst, int dstIndex ) {
        dst[ dstIndex++ ] = this.subCommand;
        dst[ dstIndex++ ] = (byte) 0x00;
        return 2;
    }


    @Override
    int writeParametersWireFormat ( byte[] dst, int dstIndex ) {
        int start = dstIndex;

        SMBUtil.writeInt2(this.informationLevel, dst, dstIndex);
        dstIndex += 2;
        dst[ dstIndex++ ] = (byte) 0x00;
        dst[ dstIndex++ ] = (byte) 0x00;
        dst[ dstIndex++ ] = (byte) 0x00;
        dst[ dstIndex++ ] = (byte) 0x00;
        dstIndex += writeString(this.path, dst, dstIndex);

        return dstIndex - start;
    }


    @Override
    int writeDataWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    int readSetupWireFormat ( byte[] buffer, int bufferIndex, int len ) {
        return 0;
    }


    @Override
    int readParametersWireFormat ( byte[] buffer, int bufferIndex, int len ) {
        return 0;
    }


    @Override
    int readDataWireFormat ( byte[] buffer, int bufferIndex, int len ) {
        return 0;
    }


    @Override
    public String toString () {
        return new String(
            "Trans2QueryPathInformation[" + super.toString() + ",informationLevel=0x" + Hexdump.toHexString(this.informationLevel, 3) + ",filename="
                    + this.path + "]");
    }
}
