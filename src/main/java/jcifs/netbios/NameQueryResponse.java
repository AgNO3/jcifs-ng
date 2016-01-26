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

package jcifs.netbios;


import jcifs.Configuration;


class NameQueryResponse extends NameServicePacket {

    NameQueryResponse ( Configuration config ) {
        super(config);
        this.recordName = new Name(config);
    }


    @Override
    int writeBodyWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    int readBodyWireFormat ( byte[] src, int srcIndex ) {
        return readResourceRecordWireFormat(src, srcIndex);
    }


    @Override
    int writeRDataWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    int readRDataWireFormat ( byte[] src, int srcIndex ) {
        if ( this.resultCode != 0 || this.opCode != QUERY ) {
            return 0;
        }
        boolean groupName = ( ( src[ srcIndex ] & 0x80 ) == 0x80 ) ? true : false;
        int nodeType = ( src[ srcIndex ] & 0x60 ) >> 5;
        srcIndex += 2;
        int address = readInt4(src, srcIndex);
        if ( address != 0 ) {
            this.addrEntry[ this.addrIndex ] = new NbtAddress(this.recordName, address, groupName, nodeType);
        }
        else {
            this.addrEntry[ this.addrIndex ] = null;
        }

        return 6;
    }


    @Override
    public String toString () {
        return new String("NameQueryResponse[" + super.toString() + ",addrEntry=" + this.addrEntry + "]");
    }
}
