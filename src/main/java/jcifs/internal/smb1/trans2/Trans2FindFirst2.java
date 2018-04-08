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

package jcifs.internal.smb1.trans2;


import jcifs.Configuration;
import jcifs.internal.smb1.trans.SmbComTransaction;
import jcifs.internal.util.SMBUtil;
import jcifs.util.Hexdump;


/**
 * 
 * @author mbechler
 *
 */
public class Trans2FindFirst2 extends SmbComTransaction {

    // flags

    static final int FLAGS_CLOSE_AFTER_THIS_REQUEST = 0x01;
    static final int FLAGS_CLOSE_IF_END_REACHED = 0x02;
    static final int FLAGS_RETURN_RESUME_KEYS = 0x04;
    static final int FLAGS_RESUME_FROM_PREVIOUS_END = 0x08;
    static final int FLAGS_FIND_WITH_BACKUP_INTENT = 0x10;

    private int searchAttributes;
    private int tflags;
    private int informationLevel;
    private int searchStorageType = 0;
    private int maxItems;
    private String wildcard;

    // information levels

    static final int SMB_INFO_STANDARD = 1;
    static final int SMB_INFO_QUERY_EA_SIZE = 2;
    static final int SMB_INFO_QUERY_EAS_FROM_LIST = 3;
    static final int SMB_FIND_FILE_DIRECTORY_INFO = 0x101;
    static final int SMB_FIND_FILE_FULL_DIRECTORY_INFO = 0x102;
    static final int SMB_FILE_NAMES_INFO = 0x103;
    static final int SMB_FILE_BOTH_DIRECTORY_INFO = 0x104;


    /**
     * 
     * @param config
     * @param filename
     * @param wildcard
     * @param searchAttributes
     * @param batchCount
     * @param batchSize
     */
    public Trans2FindFirst2 ( Configuration config, String filename, String wildcard, int searchAttributes, int batchCount, int batchSize ) {
        super(config, SMB_COM_TRANSACTION2, TRANS2_FIND_FIRST2);
        if ( filename.equals("\\") ) {
            this.path = filename;
        }
        else if ( filename.charAt(filename.length() - 1) != '\\' ) {
            this.path = filename + "\\";
        }
        else {
            this.path = filename;
        }
        this.wildcard = wildcard;
        this.searchAttributes = searchAttributes & 0x37; /* generally ignored tho */

        this.tflags = 0x00;
        this.informationLevel = SMB_FILE_BOTH_DIRECTORY_INFO;

        this.totalDataCount = 0;
        this.maxParameterCount = 10;
        this.maxItems = batchCount;
        this.maxDataCount = batchSize;
        this.maxSetupCount = 0;
    }


    @Override
    protected int writeSetupWireFormat ( byte[] dst, int dstIndex ) {
        dst[ dstIndex++ ] = getSubCommand();
        dst[ dstIndex++ ] = (byte) 0x00;
        return 2;
    }


    @Override
    protected int writeParametersWireFormat ( byte[] dst, int dstIndex ) {
        int start = dstIndex;

        SMBUtil.writeInt2(this.searchAttributes, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt2(this.maxItems, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt2(this.tflags, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt2(this.informationLevel, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt4(this.searchStorageType, dst, dstIndex);
        dstIndex += 4;
        dstIndex += writeString(this.path + this.wildcard, dst, dstIndex);

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
            "Trans2FindFirst2[" + super.toString() + ",searchAttributes=0x" + Hexdump.toHexString(this.searchAttributes, 2) + ",searchCount="
                    + this.maxItems + ",flags=0x" + Hexdump.toHexString(this.tflags, 2) + ",informationLevel=0x"
                    + Hexdump.toHexString(this.informationLevel, 3) + ",searchStorageType=" + this.searchStorageType + ",filename=" + this.path
                    + "]");
    }
}
