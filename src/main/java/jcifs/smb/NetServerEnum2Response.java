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


import org.apache.log4j.Logger;

import jcifs.Configuration;
import jcifs.util.Hexdump;


class NetServerEnum2Response extends SmbComTransactionResponse {

    private static final Logger log = Logger.getLogger(NetServerEnum2Response.class);

    class ServerInfo1 implements FileEntry {

        String name;
        int versionMajor;
        int versionMinor;
        int type;
        String commentOrMasterBrowser;


        @Override
        public String getName () {
            return this.name;
        }


        @Override
        public int getType () {
            return ( this.type & 0x80000000 ) != 0 ? SmbFile.TYPE_WORKGROUP : SmbFile.TYPE_SERVER;
        }


        @Override
        public int getAttributes () {
            return SmbFile.ATTR_READONLY | SmbFile.ATTR_DIRECTORY;
        }


        @Override
        public long createTime () {
            return 0L;
        }


        @Override
        public long lastModified () {
            return 0L;
        }


        @Override
        public long lastAccess () {
            return 0L;
        }


        @Override
        public long length () {
            return 0L;
        }


        @Override
        public String toString () {
            return new String(
                "ServerInfo1[" + "name=" + this.name + ",versionMajor=" + this.versionMajor + ",versionMinor=" + this.versionMinor + ",type=0x"
                        + Hexdump.toHexString(this.type, 8) + ",commentOrMasterBrowser=" + this.commentOrMasterBrowser + "]");
        }
    }

    private int converter, totalAvailableEntries;

    String lastName;


    NetServerEnum2Response ( Configuration config ) {
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
        ServerInfo1 e = null;

        this.results = new ServerInfo1[this.numEntries];
        for ( int i = 0; i < this.numEntries; i++ ) {
            this.results[ i ] = e = new ServerInfo1();
            e.name = readString(buffer, bufferIndex, 16, false);
            bufferIndex += 16;
            e.versionMajor = buffer[ bufferIndex++ ] & 0xFF;
            e.versionMinor = buffer[ bufferIndex++ ] & 0xFF;
            e.type = SMBUtil.readInt4(buffer, bufferIndex);
            bufferIndex += 4;
            int off = SMBUtil.readInt4(buffer, bufferIndex);
            bufferIndex += 4;
            off = ( off & 0xFFFF ) - this.converter;
            off = start + off;
            e.commentOrMasterBrowser = readString(buffer, off, 48, false);

            if ( log.isTraceEnabled() ) {
                log.trace(e);
            }
        }
        this.lastName = e == null ? null : e.name;

        return bufferIndex - start;
    }


    @Override
    public String toString () {
        return new String(
            "NetServerEnum2Response[" + super.toString() + ",status=" + this.status + ",converter=" + this.converter + ",entriesReturned="
                    + this.numEntries + ",totalAvailableEntries=" + this.totalAvailableEntries + ",lastName=" + this.lastName + "]");
    }
}
