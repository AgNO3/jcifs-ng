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

package jcifs.internal.smb1.net;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.Configuration;
import jcifs.SmbConstants;
import jcifs.internal.smb1.trans.SmbComTransactionResponse;
import jcifs.internal.util.SMBUtil;
import jcifs.smb.FileEntry;
import jcifs.util.Hexdump;


/**
 * 
 * @author mbechler
 *
 */
public class NetServerEnum2Response extends SmbComTransactionResponse {

    private static final Logger log = LoggerFactory.getLogger(NetServerEnum2Response.class);

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
            return ( this.type & 0x80000000 ) != 0 ? SmbConstants.TYPE_WORKGROUP : SmbConstants.TYPE_SERVER;
        }


        @Override
        public int getAttributes () {
            return SmbConstants.ATTR_READONLY | SmbConstants.ATTR_DIRECTORY;
        }


        /**
         * {@inheritDoc}
         *
         * @see jcifs.smb.FileEntry#getFileIndex()
         */
        @Override
        public int getFileIndex () {
            return 0;
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

    private String lastName;


    /**
     * 
     * @param config
     */
    public NetServerEnum2Response ( Configuration config ) {
        super(config);
    }


    /**
     * @return the lastName
     */
    public final String getLastName () {
        return this.lastName;
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
        ServerInfo1 e = null;
        ServerInfo1[] results = new ServerInfo1[getNumEntries()];
        for ( int i = 0; i < getNumEntries(); i++ ) {
            results[ i ] = e = new ServerInfo1();
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
                log.trace(e.toString());
            }
        }
        setResults(results);
        this.lastName = e == null ? null : e.name;
        return bufferIndex - start;
    }


    @Override
    public String toString () {
        return new String(
            "NetServerEnum2Response[" + super.toString() + ",status=" + this.getStatus() + ",converter=" + this.converter + ",entriesReturned="
                    + this.getNumEntries() + ",totalAvailableEntries=" + this.totalAvailableEntries + ",lastName=" + this.lastName + "]");
    }
}
