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

package jcifs.internal.smb1.net;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.Configuration;
import jcifs.internal.smb1.trans.SmbComTransactionResponse;
import jcifs.internal.util.SMBUtil;


/**
 * 
 */
public class NetShareEnumResponse extends SmbComTransactionResponse {

    private static final Logger log = LoggerFactory.getLogger(NetShareEnumResponse.class);

    private int converter, totalAvailableEntries;


    /**
     * 
     * @param config
     */
    public NetShareEnumResponse ( Configuration config ) {
        super(config);
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
        int start = bufferIndex;

        setStatus(SMBUtil.readInt2(buffer, bufferIndex));
        bufferIndex += 2;
        this.converter = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        setNumEntries(SMBUtil.readInt2(buffer, bufferIndex));
        bufferIndex += 2;
        this.totalAvailableEntries = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;

        return bufferIndex - start;
    }


    @Override
    protected int readDataWireFormat ( byte[] buffer, int bufferIndex, int len ) {
        int start = bufferIndex;
        SmbShareInfo e;

        setUseUnicode(false);

        SmbShareInfo[] results = new SmbShareInfo[getNumEntries()];
        for ( int i = 0; i < getNumEntries(); i++ ) {
            results[ i ] = e = new SmbShareInfo();
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
                log.trace(e.toString());
            }
        }
        setResults(results);

        return bufferIndex - start;
    }


    @Override
    public String toString () {
        return new String(
            "NetShareEnumResponse[" + super.toString() + ",status=" + getStatus() + ",converter=" + this.converter + ",entriesReturned="
                    + getNumEntries() + ",totalAvailableEntries=" + this.totalAvailableEntries + "]");
    }
}
