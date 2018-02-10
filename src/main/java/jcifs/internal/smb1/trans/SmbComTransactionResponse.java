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

package jcifs.internal.smb1.trans;


import java.util.Enumeration;

import jcifs.Configuration;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.smb1.ServerMessageBlock;
import jcifs.internal.util.SMBUtil;
import jcifs.smb.FileEntry;


/**
 * 
 */
public abstract class SmbComTransactionResponse extends ServerMessageBlock implements Enumeration<SmbComTransactionResponse> {

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
    volatile boolean hasMore = true;
    volatile boolean isPrimary = true;
    byte[] txn_buf;

    /* for doNetEnum and doFindFirstNext */
    private int status;
    private int numEntries;
    private FileEntry[] results;


    protected SmbComTransactionResponse ( Configuration config ) {
        super(config);
    }


    protected SmbComTransactionResponse ( Configuration config, byte command, byte subcommand ) {
        super(config, command);
        this.subCommand = subcommand;
    }


    /**
     * @return the dataCount
     */
    protected final int getDataCount () {
        return this.dataCount;
    }


    /**
     * @param dataCount
     *            the dataCount to set
     */
    public final void setDataCount ( int dataCount ) {
        this.dataCount = dataCount;
    }


    /**
     * @param buffer
     */
    public void setBuffer ( byte[] buffer ) {
        this.txn_buf = buffer;
    }


    /**
     * @return the txn_buf
     */
    public byte[] releaseBuffer () {
        byte[] buf = this.txn_buf;
        this.txn_buf = null;
        return buf;
    }


    /**
     * @return the subCommand
     */
    public final byte getSubCommand () {
        return this.subCommand;
    }


    /**
     * @param subCommand
     *            the subCommand to set
     */
    public final void setSubCommand ( byte subCommand ) {
        this.subCommand = subCommand;
    }


    /**
     * @return the status
     */
    public final int getStatus () {
        return this.status;
    }


    /**
     * @param status
     *            the status to set
     */
    protected final void setStatus ( int status ) {
        this.status = status;
    }


    /**
     * @return the numEntries
     */
    public final int getNumEntries () {
        return this.numEntries;
    }


    /**
     * @param numEntries
     *            the numEntries to set
     */
    protected final void setNumEntries ( int numEntries ) {
        this.numEntries = numEntries;
    }


    /**
     * @return the results
     */
    public final FileEntry[] getResults () {
        return this.results;
    }


    /**
     * @param results
     *            the results to set
     */
    protected final void setResults ( FileEntry[] results ) {
        this.results = results;
    }


    @Override
    public void reset () {
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
    protected int writeParameterWordsWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    protected int writeBytesWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb1.ServerMessageBlock#decode(byte[], int)
     */
    @Override
    public int decode ( byte[] buffer, int bufferIndex ) throws SMBProtocolDecodingException {
        int len = super.decode(buffer, bufferIndex);
        if ( this.byteCount == 0 ) {
            // otherwise hasMore may not be correctly set
            readBytesWireFormat(buffer, len + bufferIndex);
        }
        nextElement();
        return len;
    }


    @Override
    protected int readParameterWordsWireFormat ( byte[] buffer, int bufferIndex ) {
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

        return bufferIndex - start;
    }


    @Override
    protected int readBytesWireFormat ( byte[] buffer, int bufferIndex ) throws SMBProtocolDecodingException {
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
            readParametersWireFormat(this.txn_buf, this.bufParameterStart, this.totalParameterCount);
            readDataWireFormat(this.txn_buf, this.bufDataStart, this.totalDataCount);
            this.hasMore = false;
        }

        return this.pad + this.parameterCount + this.pad1 + this.dataCount;
    }


    protected abstract int writeSetupWireFormat ( byte[] dst, int dstIndex );


    protected abstract int writeParametersWireFormat ( byte[] dst, int dstIndex );


    protected abstract int writeDataWireFormat ( byte[] dst, int dstIndex );


    protected abstract int readSetupWireFormat ( byte[] buffer, int bufferIndex, int len );


    protected abstract int readParametersWireFormat ( byte[] buffer, int bufferIndex, int len ) throws SMBProtocolDecodingException;


    protected abstract int readDataWireFormat ( byte[] buffer, int bufferIndex, int len ) throws SMBProtocolDecodingException;


    @Override
    public String toString () {
        return new String(
            super.toString() + ",totalParameterCount=" + this.totalParameterCount + ",totalDataCount=" + this.totalDataCount + ",parameterCount="
                    + this.parameterCount + ",parameterOffset=" + this.parameterOffset + ",parameterDisplacement=" + this.parameterDisplacement
                    + ",dataCount=" + this.dataCount + ",dataOffset=" + this.dataOffset + ",dataDisplacement=" + this.dataDisplacement
                    + ",setupCount=" + this.setupCount + ",pad=" + this.pad + ",pad1=" + this.pad1);
    }
}
