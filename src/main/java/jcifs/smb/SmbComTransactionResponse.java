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

import org.apache.log4j.Logger;

import jcifs.Configuration;


abstract class SmbComTransactionResponse extends ServerMessageBlock implements Enumeration<SmbComTransactionResponse> {

    private static final Logger log = Logger.getLogger(SmbComNtTransactionResponse.class);

    // relative to headerStart
    static final int SETUP_OFFSET = 61;

    static final int DISCONNECT_TID = 0x01;
    static final int ONE_WAY_TRANSACTION = 0x02;

    private int pad;
    private int pad1;
    private boolean parametersDone, dataDone;

    protected int totalParameterCount;
    protected int totalDataCount;
    protected int parameterCount;
    protected int parameterOffset;
    protected int parameterDisplacement;
    protected int dataOffset;
    protected int dataDisplacement;
    protected int setupCount;
    protected int bufParameterStart;
    protected int bufDataStart;

    int dataCount;
    byte subCommand;
    boolean hasMore = true;
    boolean isPrimary = true;
    byte[] txn_buf;

    /* for doNetEnum and doFindFirstNext */
    int status;
    int numEntries;
    FileEntry[] results;


    SmbComTransactionResponse ( Configuration config ) {
        super(config);
        this.txn_buf = null;
    }


    @Override
    void reset () {
        super.reset();
        this.bufDataStart = 0;
        this.isPrimary = this.hasMore = true;
        this.parametersDone = this.dataDone = false;
    }


    @Override
    public boolean hasMoreElements () {
        return this.errorCode == 0 && this.hasMore;
    }


    @Override
    public SmbComTransactionResponse nextElement () {
        if ( this.isPrimary ) {
            this.isPrimary = false;
        }
        return this;
    }


    @Override
    int writeParameterWordsWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    int writeBytesWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    int readParameterWordsWireFormat ( byte[] buffer, int bufferIndex ) {
        int start = bufferIndex;

        this.totalParameterCount = SMBUtil.readInt2(buffer, bufferIndex);
        if ( this.bufDataStart == 0 ) {
            this.bufDataStart = this.totalParameterCount;
        }
        bufferIndex += 2;
        this.totalDataCount = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 4; // Reserved
        this.parameterCount = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.parameterOffset = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.parameterDisplacement = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.dataCount = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.dataOffset = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.dataDisplacement = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.setupCount = buffer[ bufferIndex ] & 0xFF;
        bufferIndex += 2;
        if ( this.setupCount != 0 ) {
            if ( log.isInfoEnabled() ) {
                log.info("setupCount is not zero: " + this.setupCount);
            }
        }

        return bufferIndex - start;
    }


    @Override
    int readBytesWireFormat ( byte[] buffer, int bufferIndex ) {
        this.pad = this.pad1 = 0;
        if ( this.parameterCount > 0 ) {
            bufferIndex += this.pad = this.parameterOffset - ( bufferIndex - this.headerStart );
            System.arraycopy(buffer, bufferIndex, this.txn_buf, this.bufParameterStart + this.parameterDisplacement, this.parameterCount);
            bufferIndex += this.parameterCount;
        }
        if ( this.dataCount > 0 ) {
            bufferIndex += this.pad1 = this.dataOffset - ( bufferIndex - this.headerStart );
            System.arraycopy(buffer, bufferIndex, this.txn_buf, this.bufDataStart + this.dataDisplacement, this.dataCount);
            bufferIndex += this.dataCount;
        }

        /*
         * Check to see if the entire transaction has been
         * read. If so call the read methods.
         */

        if ( !this.parametersDone && ( this.parameterDisplacement + this.parameterCount ) == this.totalParameterCount ) {
            this.parametersDone = true;
        }

        if ( !this.dataDone && ( this.dataDisplacement + this.dataCount ) == this.totalDataCount ) {
            this.dataDone = true;
        }

        if ( this.parametersDone && this.dataDone ) {
            this.hasMore = false;
            readParametersWireFormat(this.txn_buf, this.bufParameterStart, this.totalParameterCount);
            readDataWireFormat(this.txn_buf, this.bufDataStart, this.totalDataCount);
        }

        return this.pad + this.parameterCount + this.pad1 + this.dataCount;
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
            super.toString() + ",totalParameterCount=" + this.totalParameterCount + ",totalDataCount=" + this.totalDataCount + ",parameterCount="
                    + this.parameterCount + ",parameterOffset=" + this.parameterOffset + ",parameterDisplacement=" + this.parameterDisplacement
                    + ",dataCount=" + this.dataCount + ",dataOffset=" + this.dataOffset + ",dataDisplacement=" + this.dataDisplacement
                    + ",setupCount=" + this.setupCount + ",pad=" + this.pad + ",pad1=" + this.pad1);
    }
}
