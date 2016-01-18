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


import java.util.Enumeration;

import jcifs.Configuration;
import jcifs.util.Hexdump;


abstract class SmbComTransaction extends ServerMessageBlock implements Enumeration<SmbComTransaction> {

    // relative to headerStart
    private static final int PRIMARY_SETUP_OFFSET = 61;
    private static final int SECONDARY_PARAMETER_OFFSET = 51;

    static final int DISCONNECT_TID = 0x01;
    static final int ONE_WAY_TRANSACTION = 0x02;

    static final int PADDING_SIZE = 2;

    private int tflags = 0x00;
    private int pad = 0;
    private int pad1 = 0;
    private boolean hasMore = true;
    private boolean isPrimary = true;
    private int bufParameterOffset;
    private int bufDataOffset;

    static final int TRANSACTION_BUF_SIZE = 0xFFFF;

    static final byte TRANS2_FIND_FIRST2 = (byte) 0x01;
    static final byte TRANS2_FIND_NEXT2 = (byte) 0x02;
    static final byte TRANS2_QUERY_FS_INFORMATION = (byte) 0x03;
    static final byte TRANS2_QUERY_PATH_INFORMATION = (byte) 0x05;
    static final byte TRANS2_GET_DFS_REFERRAL = (byte) 0x10;
    static final byte TRANS2_QUERY_FILE_INFORMATION = (byte) 0x07;
    static final byte TRANS2_SET_FILE_INFORMATION = (byte) 0x08;

    static final int NET_SHARE_ENUM = 0x0000;
    static final int NET_SERVER_ENUM2 = 0x0068;
    static final int NET_SERVER_ENUM3 = 0x00D7;

    static final byte TRANS_PEEK_NAMED_PIPE = (byte) 0x23;
    static final byte TRANS_WAIT_NAMED_PIPE = (byte) 0x53;
    static final byte TRANS_CALL_NAMED_PIPE = (byte) 0x54;
    static final byte TRANS_TRANSACT_NAMED_PIPE = (byte) 0x26;

    protected int primarySetupOffset;
    protected int secondaryParameterOffset;
    protected int parameterCount;
    protected int parameterOffset;
    protected int parameterDisplacement;
    protected int dataCount;
    protected int dataOffset;
    protected int dataDisplacement;

    int totalParameterCount;
    int totalDataCount;
    int maxParameterCount;
    int maxDataCount;
    byte maxSetupCount;
    int timeout = 0;
    int setupCount = 1;
    byte subCommand;
    String name = "";
    int maxBufferSize; // set in SmbTransport.sendTransaction() before nextElement called

    byte[] txn_buf;


    SmbComTransaction ( Configuration config ) {
        super(config);
        this.maxDataCount = config.getTransactionBufferSize() - 512;
        this.maxParameterCount = 1024;
        this.primarySetupOffset = PRIMARY_SETUP_OFFSET;
        this.secondaryParameterOffset = SECONDARY_PARAMETER_OFFSET;
    }


    @Override
    void reset () {
        super.reset();
        this.isPrimary = this.hasMore = true;
    }


    void reset ( int key, String lastName ) {
        reset();
    }


    @Override
    public boolean hasMoreElements () {
        return this.hasMore;
    }


    @Override
    public SmbComTransaction nextElement () {
        if ( this.isPrimary ) {
            this.isPrimary = false;

            this.parameterOffset = this.primarySetupOffset + ( this.setupCount * 2 ) + 2;
            if ( this.command != SMB_COM_NT_TRANSACT ) {
                if ( this.command == SMB_COM_TRANSACTION && isResponse() == false ) {
                    this.parameterOffset += stringWireLength(this.name, this.parameterOffset);
                }
            }
            else if ( this.command == SMB_COM_NT_TRANSACT ) {
                this.parameterOffset += 2;
            }
            this.pad = this.parameterOffset % PADDING_SIZE;
            this.pad = this.pad == 0 ? 0 : PADDING_SIZE - this.pad;
            this.parameterOffset += this.pad;

            this.totalParameterCount = writeParametersWireFormat(this.txn_buf, this.bufParameterOffset);
            this.bufDataOffset = this.totalParameterCount; // data comes right after data

            int available = this.maxBufferSize - this.parameterOffset;
            this.parameterCount = Math.min(this.totalParameterCount, available);
            available -= this.parameterCount;

            this.dataOffset = this.parameterOffset + this.parameterCount;
            this.pad1 = this.dataOffset % PADDING_SIZE;
            this.pad1 = this.pad1 == 0 ? 0 : PADDING_SIZE - this.pad1;
            this.dataOffset += this.pad1;

            this.totalDataCount = writeDataWireFormat(this.txn_buf, this.bufDataOffset);

            this.dataCount = Math.min(this.totalDataCount, available);
        }
        else {
            if ( this.command != SMB_COM_NT_TRANSACT ) {
                this.command = SMB_COM_TRANSACTION_SECONDARY;
            }
            else {
                this.command = SMB_COM_NT_TRANSACT_SECONDARY;
            }
            // totalParameterCount and totalDataCount are set ok from primary

            this.parameterOffset = SECONDARY_PARAMETER_OFFSET;
            if ( ( this.totalParameterCount - this.parameterDisplacement ) > 0 ) {
                this.pad = this.parameterOffset % PADDING_SIZE;
                this.pad = this.pad == 0 ? 0 : PADDING_SIZE - this.pad;
                this.parameterOffset += this.pad;
            }

            // caclulate parameterDisplacement before calculating new parameterCount
            this.parameterDisplacement += this.parameterCount;

            int available = this.maxBufferSize - this.parameterOffset - this.pad;
            this.parameterCount = Math.min(this.totalParameterCount - this.parameterDisplacement, available);
            available -= this.parameterCount;

            this.dataOffset = this.parameterOffset + this.parameterCount;
            this.pad1 = this.dataOffset % PADDING_SIZE;
            this.pad1 = this.pad1 == 0 ? 0 : PADDING_SIZE - this.pad1;
            this.dataOffset += this.pad1;

            this.dataDisplacement += this.dataCount;

            available -= this.pad1;
            this.dataCount = Math.min(this.totalDataCount - this.dataDisplacement, available);
        }
        if ( ( this.parameterDisplacement + this.parameterCount ) >= this.totalParameterCount
                && ( this.dataDisplacement + this.dataCount ) >= this.totalDataCount ) {
            this.hasMore = false;
        }
        return this;
    }


    @Override
    int writeParameterWordsWireFormat ( byte[] dst, int dstIndex ) {
        int start = dstIndex;

        SMBUtil.writeInt2(this.totalParameterCount, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt2(this.totalDataCount, dst, dstIndex);
        dstIndex += 2;
        if ( this.command != SMB_COM_TRANSACTION_SECONDARY ) {
            SMBUtil.writeInt2(this.maxParameterCount, dst, dstIndex);
            dstIndex += 2;
            SMBUtil.writeInt2(this.maxDataCount, dst, dstIndex);
            dstIndex += 2;
            dst[ dstIndex++ ] = this.maxSetupCount;
            dst[ dstIndex++ ] = (byte) 0x00; // Reserved1
            SMBUtil.writeInt2(this.tflags, dst, dstIndex);
            dstIndex += 2;
            SMBUtil.writeInt4(this.timeout, dst, dstIndex);
            dstIndex += 4;
            dst[ dstIndex++ ] = (byte) 0x00; // Reserved2
            dst[ dstIndex++ ] = (byte) 0x00;
        }
        SMBUtil.writeInt2(this.parameterCount, dst, dstIndex);
        dstIndex += 2;
        // writeInt2(( parameterCount == 0 ? 0 : parameterOffset ), dst, dstIndex );
        SMBUtil.writeInt2(this.parameterOffset, dst, dstIndex);
        dstIndex += 2;
        if ( this.command == SMB_COM_TRANSACTION_SECONDARY ) {
            SMBUtil.writeInt2(this.parameterDisplacement, dst, dstIndex);
            dstIndex += 2;
        }
        SMBUtil.writeInt2(this.dataCount, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt2( ( this.dataCount == 0 ? 0 : this.dataOffset ), dst, dstIndex);
        dstIndex += 2;
        if ( this.command == SMB_COM_TRANSACTION_SECONDARY ) {
            SMBUtil.writeInt2(this.dataDisplacement, dst, dstIndex);
            dstIndex += 2;
        }
        else {
            dst[ dstIndex++ ] = (byte) this.setupCount;
            dst[ dstIndex++ ] = (byte) 0x00; // Reserved3
            dstIndex += writeSetupWireFormat(dst, dstIndex);
        }

        return dstIndex - start;
    }


    @Override
    int writeBytesWireFormat ( byte[] dst, int dstIndex ) {
        int start = dstIndex;
        int p = this.pad;

        if ( this.command == SMB_COM_TRANSACTION && isResponse() == false ) {
            dstIndex += writeString(this.name, dst, dstIndex);
        }

        if ( this.parameterCount > 0 ) {
            while ( p-- > 0 ) {
                dst[ dstIndex++ ] = (byte) 0x00; // Pad
            }

            System.arraycopy(this.txn_buf, this.bufParameterOffset, dst, dstIndex, this.parameterCount);
            dstIndex += this.parameterCount;
        }

        if ( this.dataCount > 0 ) {
            p = this.pad1;
            while ( p-- > 0 ) {
                dst[ dstIndex++ ] = (byte) 0x00; // Pad1
            }
            System.arraycopy(this.txn_buf, this.bufDataOffset, dst, dstIndex, this.dataCount);
            this.bufDataOffset += this.dataCount;
            dstIndex += this.dataCount;
        }

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


    abstract int writeSetupWireFormat ( byte[] dst, int dstIndex );


    abstract int writeParametersWireFormat ( byte[] dst, int dstIndex );


    abstract int writeDataWireFormat ( byte[] dst, int dstIndex );


    abstract int readSetupWireFormat ( byte[] buffer, int bufferIndex, int len );


    abstract int readParametersWireFormat ( byte[] buffer, int bufferIndex, int len );


    abstract int readDataWireFormat ( byte[] buffer, int bufferIndex, int len );


    @Override
    public String toString () {
        return new String(
            super.toString() + ",totalParameterCount=" + this.totalParameterCount + ",totalDataCount=" + this.totalDataCount + ",maxParameterCount="
                    + this.maxParameterCount + ",maxDataCount=" + this.maxDataCount + ",maxSetupCount=" + (int) this.maxSetupCount + ",flags=0x"
                    + Hexdump.toHexString(this.tflags, 2) + ",timeout=" + this.timeout + ",parameterCount=" + this.parameterCount
                    + ",parameterOffset=" + this.parameterOffset + ",parameterDisplacement=" + this.parameterDisplacement + ",dataCount="
                    + this.dataCount + ",dataOffset=" + this.dataOffset + ",dataDisplacement=" + this.dataDisplacement + ",setupCount="
                    + this.setupCount + ",pad=" + this.pad + ",pad1=" + this.pad1);
    }
}
