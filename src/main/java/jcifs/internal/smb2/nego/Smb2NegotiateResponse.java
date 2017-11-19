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
package jcifs.internal.smb2.nego;


import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.internal.CommonServerMessageBlock;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.SmbNegotiationResponse;
import jcifs.internal.smb2.ServerMessageBlock2Response;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.smb2.io.Smb2ReadResponse;
import jcifs.internal.smb2.io.Smb2WriteRequest;
import jcifs.internal.util.SMBUtil;
import jcifs.util.Hexdump;
import jcifs.util.transport.Response;


/**
 * @author mbechler
 *
 */
public class Smb2NegotiateResponse extends ServerMessageBlock2Response implements SmbNegotiationResponse {

    private static final Logger log = LoggerFactory.getLogger(Smb2NegotiateResponse.class);

    private int securityMode;
    private int dialectRevision;
    private byte[] serverGuid = new byte[16];
    private int capabilities;
    private int maxTransactSize;
    private int maxReadSize;
    private int maxWriteSize;
    private long systemTime;
    private long serverStartTime;
    private NegotiateContextResponse[] negotiateContexts;
    private byte[] securityBuffer;


    /**
     * 
     * @param cfg
     */
    public Smb2NegotiateResponse ( Configuration cfg ) {
        super(cfg);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbNegotiationResponse#getInitialCredits()
     */
    @Override
    public int getInitialCredits () {
        return getCredit();
    }


    /**
     * @return the dialectRevision
     */
    public int getDialectRevision () {
        return this.dialectRevision;
    }


    /**
     * @return the capabilities
     */
    public final int getCapabilities () {
        return this.capabilities;
    }


    /**
     * @return initial security blob
     */
    public byte[] getSecurityBlob () {
        return this.securityBuffer;
    }


    /**
     * @return the maxTransactSize
     */
    public int getMaxTransactSize () {
        return this.maxTransactSize;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbNegotiationResponse#getTransactionBufferSize()
     */
    @Override
    public int getTransactionBufferSize () {
        return getMaxTransactSize();
    }


    /**
     * @return the negotiateContexts
     */
    public NegotiateContextResponse[] getNegotiateContexts () {
        return this.negotiateContexts;
    }


    /**
     * @return the serverStartTime
     */
    public long getServerStartTime () {
        return this.serverStartTime;
    }


    /**
     * @return the securityMode
     */
    public int getSecurityMode () {
        return this.securityMode;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbNegotiationResponse#haveCapabilitiy(int)
     */
    @Override
    public boolean haveCapabilitiy ( int cap ) {
        return ( this.capabilities & cap ) == cap;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbNegotiationResponse#isDFSSupported()
     */
    @Override
    public boolean isDFSSupported () {
        return !getConfig().isDfsDisabled() && haveCapabilitiy(Smb2Constants.SMB2_GLOBAL_CAP_DFS);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbNegotiationResponse#canReuse(jcifs.CIFSContext, boolean)
     */
    @Override
    public boolean canReuse ( CIFSContext tc, boolean forceSigning ) {
        return getConfig().equals(tc.getConfig());
    }


    /**
     * 
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbNegotiationResponse#isValid(jcifs.CIFSContext, boolean)
     */
    @Override
    public boolean isValid ( CIFSContext tc, boolean signingEnforced ) {
        if ( !isReceived() || this.getStatus() != 0 ) {
            return false;
        }

        if ( signingEnforced && !isSigningEnabled() ) {
            log.error("Signing is enforced but server does not allow it");
            return false;
        }

        if ( getDialectRevision() == Smb2Constants.SMB2_DIALECT_ANY ) {
            log.error("Server returned ANY dialect");
            return false;
        }

        int maxBufferSize = tc.getConfig().getTransactionBufferSize();
        this.maxReadSize = Math.min(maxBufferSize - Smb2ReadResponse.OVERHEAD, Math.min(tc.getConfig().getRecieveBufferSize(), this.maxReadSize))
                & ~0x7;
        this.maxWriteSize = Math.min(maxBufferSize - Smb2WriteRequest.OVERHEAD, Math.min(tc.getConfig().getSendBufferSize(), this.maxWriteSize))
                & ~0x7;
        this.maxTransactSize = Math.min(maxBufferSize - 512, this.maxTransactSize) & ~0x7;

        return true;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbNegotiationResponse#getReceiveBufferSize()
     */
    @Override
    public int getReceiveBufferSize () {
        return this.maxReadSize;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbNegotiationResponse#getSendBufferSize()
     */
    @Override
    public int getSendBufferSize () {
        return this.maxWriteSize;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbNegotiationResponse#isSigningEnabled()
     */
    @Override
    public boolean isSigningEnabled () {
        return ( this.securityMode & ( Smb2Constants.SMB2_NEGOTIATE_SIGNING_ENABLED | Smb2Constants.SMB2_NEGOTIATE_SIGNING_REQUIRED ) ) != 0;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbNegotiationResponse#isSigningRequired()
     */
    @Override
    public boolean isSigningRequired () {
        return ( this.securityMode & Smb2Constants.SMB2_NEGOTIATE_SIGNING_REQUIRED ) == Smb2Constants.SMB2_NEGOTIATE_SIGNING_REQUIRED;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbNegotiationResponse#isSigningNegotiated()
     */
    @Override
    public boolean isSigningNegotiated () {
        return isSigningEnabled();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbNegotiationResponse#setupRequest(jcifs.internal.CommonServerMessageBlock)
     */
    @Override
    public void setupRequest ( CommonServerMessageBlock request ) {}


    /**
     * 
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbNegotiationResponse#setupResponse(jcifs.util.transport.Response)
     */
    @Override
    public void setupResponse ( Response resp ) {}


    @Override
    protected int readBytesWireFormat ( byte[] buffer, int bufferIndex ) throws SMBProtocolDecodingException {
        int start = bufferIndex;

        int structureSize = SMBUtil.readInt2(buffer, bufferIndex);
        if ( structureSize != 65 ) {
            throw new SMBProtocolDecodingException("Structure size is not 65");
        }

        this.securityMode = SMBUtil.readInt2(buffer, bufferIndex + 2);
        bufferIndex += 4;

        this.dialectRevision = SMBUtil.readInt2(buffer, bufferIndex);
        int negotiateContextCount = SMBUtil.readInt2(buffer, bufferIndex + 2);
        bufferIndex += 4;

        System.arraycopy(buffer, bufferIndex, this.serverGuid, 0, 16);
        bufferIndex += 16;

        this.capabilities = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        this.maxTransactSize = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.maxReadSize = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.maxWriteSize = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        this.systemTime = SMBUtil.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        this.serverStartTime = SMBUtil.readTime(buffer, bufferIndex);
        bufferIndex += 8;

        int securityBufferOffset = SMBUtil.readInt2(buffer, bufferIndex);
        int securityBufferLength = SMBUtil.readInt2(buffer, bufferIndex + 2);
        bufferIndex += 4;

        int negotiateContextOffset = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        int hdrStart = getHeaderStart();
        if ( hdrStart + securityBufferOffset + securityBufferLength < buffer.length ) {
            this.securityBuffer = new byte[securityBufferLength];
            System.arraycopy(buffer, hdrStart + securityBufferOffset, this.securityBuffer, 0, securityBufferLength);
            bufferIndex += securityBufferLength;
        }

        int pad = ( bufferIndex - hdrStart ) % 8;
        bufferIndex += pad;

        if ( negotiateContextOffset != 0 && negotiateContextCount != 0 ) {
            NegotiateContextResponse[] contexts = new NegotiateContextResponse[negotiateContextCount];
            for ( int i = 0; i < negotiateContextCount; i++ ) {
                int type = SMBUtil.readInt2(buffer, bufferIndex);
                int dataLen = SMBUtil.readInt2(buffer, bufferIndex + 2);
                bufferIndex += 4;
                bufferIndex += 4; // Reserved
                NegotiateContextResponse ctx = createContext(type);
                if ( ctx != null ) {
                    ctx.decode(buffer, bufferIndex, dataLen);
                    contexts[ i ] = ctx;
                }
                bufferIndex += dataLen;
                if ( i != negotiateContextCount - 1 ) {
                    bufferIndex += pad8(bufferIndex);
                }
            }

        }

        return bufferIndex - start;
    }


    /**
     * @param type
     * @return
     */
    protected static NegotiateContextResponse createContext ( int type ) {
        return null;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#writeBytesWireFormat(byte[], int)
     */
    @Override
    protected int writeBytesWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    public String toString () {
        return new String(
            "Smb2NegotiateResponse[" + super.toString() + ",dialectRevision=" + this.dialectRevision + ",securityMode=0x"
                    + Hexdump.toHexString(this.securityMode, 1) + ",capabilities=0x" + Hexdump.toHexString(this.capabilities, 8) + ",serverTime="
                    + new Date(this.systemTime));
    }

}
