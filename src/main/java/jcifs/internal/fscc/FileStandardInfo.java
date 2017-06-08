/*
 * © 2017 AgNO3 Gmbh & Co. KG
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
package jcifs.internal.fscc;


import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.util.SMBUtil;


/**
 * 
 */
public class FileStandardInfo implements BasicFileInformation {

    private long allocationSize;
    private long endOfFile;
    private int numberOfLinks;
    private boolean deletePending;
    private boolean directory;


    @Override
    public byte getFileInformationLevel () {
        return FILE_STANDARD_INFO;
    }


    @Override
    public int getAttributes () {
        return 0;
    }


    @Override
    public long getCreateTime () {
        return 0L;
    }


    @Override
    public long getLastWriteTime () {
        return 0L;
    }


    @Override
    public long getLastAccessTime () {
        return 0L;
    }


    @Override
    public long getSize () {
        return this.endOfFile;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Decodable#decode(byte[], int, int)
     */
    @Override
    public int decode ( byte[] buffer, int bufferIndex, int len ) throws SMBProtocolDecodingException {
        int start = bufferIndex;
        this.allocationSize = SMBUtil.readInt8(buffer, bufferIndex);
        bufferIndex += 8;
        this.endOfFile = SMBUtil.readInt8(buffer, bufferIndex);
        bufferIndex += 8;
        this.numberOfLinks = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.deletePending = ( buffer[ bufferIndex++ ] & 0xFF ) > 0;
        this.directory = ( buffer[ bufferIndex++ ] & 0xFF ) > 0;
        return bufferIndex - start;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Encodable#size()
     */
    @Override
    public int size () {
        return 22;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Encodable#encode(byte[], int)
     */
    @Override
    public int encode ( byte[] dst, int dstIndex ) {
        int start = dstIndex;
        SMBUtil.writeInt8(this.allocationSize, dst, dstIndex);
        dstIndex += 8;
        SMBUtil.writeInt8(this.endOfFile, dst, dstIndex);
        dstIndex += 8;
        SMBUtil.writeInt4(this.numberOfLinks, dst, dstIndex);
        dstIndex += 4;
        dst[ dstIndex++ ] = (byte) ( this.deletePending ? 1 : 0 );
        dst[ dstIndex++ ] = (byte) ( this.directory ? 1 : 0 );
        return dstIndex - start;
    }


    @Override
    public String toString () {
        return new String(
            "SmbQueryInfoStandard[" + "allocationSize=" + this.allocationSize + ",endOfFile=" + this.endOfFile + ",numberOfLinks="
                    + this.numberOfLinks + ",deletePending=" + this.deletePending + ",directory=" + this.directory + "]");
    }
}