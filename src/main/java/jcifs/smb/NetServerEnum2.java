/* jcifs smb client library in Java
 * Copyright (C) 2000  "Michael B. Allen" <jcifs at samba dot org>
 *                             Gary Rambo <grambo aventail.com>
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


import java.io.UnsupportedEncodingException;

import jcifs.Configuration;


class NetServerEnum2 extends SmbComTransaction {

    static final int SV_TYPE_ALL = 0xFFFFFFFF;
    static final int SV_TYPE_DOMAIN_ENUM = 0x80000000;

    static final String[] DESCR = {
        "WrLehDO\u0000B16BBDz\u0000", "WrLehDz\u0000B16BBDz\u0000",
    };

    String domain, lastName = null;
    int serverTypes;


    NetServerEnum2 ( Configuration config, String domain, int serverTypes ) {
        super(config);
        this.domain = domain;
        this.serverTypes = serverTypes;
        this.command = SMB_COM_TRANSACTION;
        this.subCommand = NET_SERVER_ENUM2; // not really true be used by upper logic
        this.name = "\\PIPE\\LANMAN";

        this.maxParameterCount = 8;
        this.maxDataCount = 16384;
        this.maxSetupCount = (byte) 0x00;
        this.setupCount = 0;
        this.timeout = 5000;
    }


    @Override
    void reset ( int key, String lastN ) {
        super.reset();
        this.lastName = lastN;
    }


    @Override
    int writeSetupWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    int writeParametersWireFormat ( byte[] dst, int dstIndex ) {
        int start = dstIndex;
        byte[] descr;
        int which = this.subCommand == NET_SERVER_ENUM2 ? 0 : 1;

        try {
            descr = DESCR[ which ].getBytes("ASCII");
        }
        catch ( UnsupportedEncodingException uee ) {
            return 0;
        }

        SMBUtil.writeInt2(this.subCommand & 0xFF, dst, dstIndex);
        dstIndex += 2;
        System.arraycopy(descr, 0, dst, dstIndex, descr.length);
        dstIndex += descr.length;
        SMBUtil.writeInt2(0x0001, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt2(this.maxDataCount, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt4(this.serverTypes, dst, dstIndex);
        dstIndex += 4;
        dstIndex += writeString(this.domain.toUpperCase(), dst, dstIndex, false);
        if ( which == 1 ) {
            dstIndex += writeString(this.lastName.toUpperCase(), dst, dstIndex, false);
        }

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
            "NetServerEnum2[" + super.toString() + ",name=" + this.name + ",serverTypes="
                    + ( this.serverTypes == SV_TYPE_ALL ? "SV_TYPE_ALL" : "SV_TYPE_DOMAIN_ENUM" ) + "]");
    }
}
