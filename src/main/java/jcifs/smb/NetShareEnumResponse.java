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


import org.apache.log4j.Logger;

import jcifs.Configuration;


class NetShareEnumResponse extends SmbComTransactionResponse {

    private static final Logger log = Logger.getLogger(NetShareEnumResponse.class);

    private int converter, totalAvailableEntries;


    NetShareEnumResponse ( Configuration config ) {
        super(config);
    }


    @Override
    int writeSetupWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    int writeParametersWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
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
        int start = bufferIndex;

        this.status = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.converter = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.numEntries = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.totalAvailableEntries = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;

        return bufferIndex - start;
    }


    @Override
    int readDataWireFormat ( byte[] buffer, int bufferIndex, int len ) {
        int start = bufferIndex;
        SmbShareInfo e;

        this.useUnicode = false;

        this.results = new SmbShareInfo[this.numEntries];
        for ( int i = 0; i < this.numEntries; i++ ) {
            this.results[ i ] = e = new SmbShareInfo();
            e.netName = readString(buffer, bufferIndex, 13, false);
            bufferIndex += 14;
            e.type = SMBUtil.readInt2(buffer, bufferIndex);
            bufferIndex += 2;
            int off = SMBUtil.readInt4(buffer, bufferIndex);
            bufferIndex += 4;
            off = ( off & 0xFFFF ) - this.converter;
            off = start + off;
            e.remark = readString(buffer, off, 128, false);

            if ( log.isTraceEnabled() ) {
                log.trace(e);
            }
        }

        return bufferIndex - start;
    }


    @Override
    public String toString () {
        return new String(
            "NetShareEnumResponse[" + super.toString() + ",status=" + this.status + ",converter=" + this.converter + ",entriesReturned="
                    + this.numEntries + ",totalAvailableEntries=" + this.totalAvailableEntries + "]");
    }
}
