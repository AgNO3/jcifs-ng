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
import jcifs.SmbConstants;
import jcifs.util.Hexdump;


class SmbComDelete extends ServerMessageBlock {

    private int searchAttributes;


    SmbComDelete ( Configuration config, String fileName ) {
        super(config);
        this.path = fileName;
        this.command = SMB_COM_DELETE;
        this.searchAttributes = SmbConstants.ATTR_HIDDEN | SmbConstants.ATTR_HIDDEN | SmbConstants.ATTR_SYSTEM;
    }


    @Override
    int writeParameterWordsWireFormat ( byte[] dst, int dstIndex ) {
        SMBUtil.writeInt2(this.searchAttributes, dst, dstIndex);
        return 2;
    }


    @Override
    int writeBytesWireFormat ( byte[] dst, int dstIndex ) {
        int start = dstIndex;

        dst[ dstIndex++ ] = (byte) 0x04;
        dstIndex += writeString(this.path, dst, dstIndex);

        return dstIndex - start;
    }


    @Override
    int readParameterWordsWireFormat ( byte[] buffer, int bufferIndex ) {
        return 0;
    }


    @Override
    int readBytesWireFormat ( byte[] buffer, int bufferIndex ) {
        return 0;
    }


    @Override
    public String toString () {
        return new String(
            "SmbComDelete[" + super.toString() + ",searchAttributes=0x" + Hexdump.toHexString(this.searchAttributes, 4) + ",fileName=" + this.path
                    + "]");
    }
}
