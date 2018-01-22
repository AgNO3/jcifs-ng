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

package jcifs.internal.smb1.com;


import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.DialectVersion;
import jcifs.SmbConstants;
import jcifs.internal.CommonServerMessageBlock;
import jcifs.internal.SmbNegotiationRequest;
import jcifs.internal.SmbNegotiationResponse;
import jcifs.internal.smb1.ServerMessageBlock;
import jcifs.internal.smb1.trans.SmbComTransaction;
import jcifs.internal.util.SMBUtil;
import jcifs.util.Hexdump;
import jcifs.util.Strings;
import jcifs.util.transport.Response;


/**
 * 
 */
public class SmbComNegotiateResponse extends ServerMessageBlock implements SmbNegotiationResponse {

    private static final Logger log = LoggerFactory.getLogger(SmbComNegotiateResponse.class);

    private int dialectIndex;

    /* Negotiated values */
    private ServerData server;
    private int negotiatedFlags2;
    private int maxMpxCount;
    private int snd_buf_size;
    private int recv_buf_size;
    private int tx_buf_size;

    private int capabilities;
    private int sessionKey = 0x00000000;
    private boolean useUnicode;


    /**
     * 
     * @param ctx
     */
    public SmbComNegotiateResponse ( CIFSContext ctx ) {
        super(ctx.getConfig());
        this.server = new ServerData();
        this.capabilities = ctx.getConfig().getCapabilities();
        this.negotiatedFlags2 = ctx.getConfig().getFlags2();
        this.maxMpxCount = ctx.getConfig().getMaxMpxCount();
        this.snd_buf_size = ctx.getConfig().getSendBufferSize();
        this.recv_buf_size = ctx.getConfig().getReceiveBufferSize();
        this.tx_buf_size = ctx.getConfig().getTransactionBufferSize();
        this.useUnicode = ctx.getConfig().isUseUnicode();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbNegotiationResponse#getSelectedDialect()
     */
    @Override
    public DialectVersion getSelectedDialect () {
        return DialectVersion.SMB1;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbNegotiationResponse#getTransactionBufferSize()
     */
    @Override
    public int getTransactionBufferSize () {
        return this.tx_buf_size;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbNegotiationResponse#getInitialCredits()
     */
    @Override
    public int getInitialCredits () {
        return getNegotiatedMpxCount();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbNegotiationResponse#canReuse(jcifs.CIFSContext, boolean)
     */
    @Override
    public boolean canReuse ( CIFSContext tc, boolean forceSigning ) {
        return this.getConfig().equals(tc.getConfig());
    }


    /**
     * @return the dialectIndex
     */
    public int getDialectIndex () {
        return this.dialectIndex;
    }


    /**
     * @return the negotiated capbilities
     */
    public int getNegotiatedCapabilities () {
        return this.capabilities;
    }


    /**
     * 
     * @return negotiated send buffer size
     */
    public int getNegotiatedSendBufferSize () {
        return this.snd_buf_size;
    }


    /**
     * 
     * @return negotiated multiplex count
     */
    public int getNegotiatedMpxCount () {
        return this.maxMpxCount;
    }


    /**
     * 
     * @return negotiated session key
     */
    public int getNegotiatedSessionKey () {
        return this.sessionKey;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbNegotiationResponse#getReceiveBufferSize()
     */
    @Override
    public int getReceiveBufferSize () {
        return this.recv_buf_size;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbNegotiationResponse#getSendBufferSize()
     */
    @Override
    public int getSendBufferSize () {
        return this.snd_buf_size;
    }


    /**
     * @return negotiated flags2
     */
    public int getNegotiatedFlags2 () {
        return this.negotiatedFlags2;
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
        return !getConfig().isDfsDisabled() && haveCapabilitiy(SmbConstants.CAP_DFS);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbNegotiationResponse#isSigningNegotiated()
     */
    @Override
    public boolean isSigningNegotiated () {
        return ( this.negotiatedFlags2 & SmbConstants.FLAGS2_SECURITY_SIGNATURES ) == SmbConstants.FLAGS2_SECURITY_SIGNATURES;
    }


    @Override
    public boolean isValid ( CIFSContext ctx, SmbNegotiationRequest req ) {
        if ( getDialectIndex() > 10 ) {
            return false;
        }

        if ( ( this.server.scapabilities & SmbConstants.CAP_EXTENDED_SECURITY ) != SmbConstants.CAP_EXTENDED_SECURITY
                && this.server.encryptionKeyLength != 8 && ctx.getConfig().getLanManCompatibility() == 0 ) {
            log.warn("Unexpected encryption key length: " + this.server.encryptionKeyLength);
            return false;
        }

        if ( req.isSigningEnforced() && !this.server.signaturesEnabled ) {
            log.error("Signatures are required but the server does not support them");
            return false;
        }
        else if ( req.isSigningEnforced() || this.server.signaturesRequired
                || ( this.server.signaturesEnabled && ctx.getConfig().isSigningEnabled() ) ) {
            this.negotiatedFlags2 |= SmbConstants.FLAGS2_SECURITY_SIGNATURES;
            if ( req.isSigningEnforced() || isSigningRequired() ) {
                this.negotiatedFlags2 |= SmbConstants.FLAGS2_SECURITY_REQUIRE_SIGNATURES;
            }
        }
        else {
            this.negotiatedFlags2 &= 0xFFFF ^ SmbConstants.FLAGS2_SECURITY_SIGNATURES;
            this.negotiatedFlags2 &= 0xFFFF ^ SmbConstants.FLAGS2_SECURITY_REQUIRE_SIGNATURES;
        }

        if ( log.isDebugEnabled() ) {
            log.debug(
                "Signing " + ( ( this.negotiatedFlags2 & SmbConstants.FLAGS2_SECURITY_SIGNATURES ) != 0 ? "enabled " : "not-enabled " )
                        + ( ( this.negotiatedFlags2 & SmbConstants.FLAGS2_SECURITY_REQUIRE_SIGNATURES ) != 0 ? "required" : "not-required" ));
        }

        this.maxMpxCount = Math.min(this.maxMpxCount, this.server.smaxMpxCount);
        if ( this.maxMpxCount < 1 )
            this.maxMpxCount = 1;
        this.snd_buf_size = Math.min(this.snd_buf_size, this.server.maxBufferSize);
        this.recv_buf_size = Math.min(this.recv_buf_size, this.server.maxBufferSize);
        this.tx_buf_size = Math.min(this.tx_buf_size, this.server.maxBufferSize);

        this.capabilities &= this.server.scapabilities;
        if ( ( this.server.scapabilities & SmbConstants.CAP_EXTENDED_SECURITY ) == SmbConstants.CAP_EXTENDED_SECURITY )
            this.capabilities |= SmbConstants.CAP_EXTENDED_SECURITY; // & doesn't copy high bit

        if ( ctx.getConfig().isUseUnicode() || ctx.getConfig().isForceUnicode() ) {
            this.capabilities |= SmbConstants.CAP_UNICODE;
        }

        if ( ( this.capabilities & SmbConstants.CAP_UNICODE ) == 0 ) {
            // server doesn't want unicode
            if ( ctx.getConfig().isForceUnicode() ) {
                this.capabilities |= SmbConstants.CAP_UNICODE;
                this.useUnicode = true;
            }
            else {
                this.useUnicode = false;
                this.negotiatedFlags2 &= 0xFFFF ^ SmbConstants.FLAGS2_UNICODE;
            }
        }
        else {
            this.useUnicode = ctx.getConfig().isUseUnicode();
        }

        if ( this.useUnicode ) {
            log.debug("Unicode is enabled");
        }
        else {
            log.debug("Unicode is disabled");
        }
        return true;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbNegotiationResponse#setupRequest(jcifs.internal.CommonServerMessageBlock)
     */
    @Override
    public void setupRequest ( CommonServerMessageBlock request ) {

        if ( ! ( request instanceof ServerMessageBlock ) ) {
            return;
        }

        ServerMessageBlock req = (ServerMessageBlock) request;

        req.addFlags2(this.negotiatedFlags2);
        req.setUseUnicode(req.isForceUnicode() || this.useUnicode);
        if ( req.isUseUnicode() ) {
            req.addFlags2(SmbConstants.FLAGS2_UNICODE);
        }

        if ( req instanceof SmbComTransaction ) {
            ( (SmbComTransaction) req ).setMaxBufferSize(this.snd_buf_size);
        }
    }


    /**
     * 
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbNegotiationResponse#setupResponse(jcifs.util.transport.Response)
     */
    @Override
    public void setupResponse ( Response resp ) {
        if ( ! ( resp instanceof ServerMessageBlock ) ) {
            return;
        }
        ( (ServerMessageBlock) resp ).setUseUnicode(this.useUnicode);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbNegotiationResponse#isSigningEnabled()
     */
    @Override
    public boolean isSigningEnabled () {
        return this.server.signaturesEnabled || this.server.signaturesRequired;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbNegotiationResponse#isSigningRequired()
     */
    @Override
    public boolean isSigningRequired () {
        return this.server.signaturesRequired;
    }


    /**
     * @return the server
     */
    public ServerData getServerData () {
        return this.server;
    }


    @Override
    protected int writeParameterWordsWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    protected int writeBytesWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    protected int readParameterWordsWireFormat ( byte[] buffer, int bufferIndex ) {
        int start = bufferIndex;

        this.dialectIndex = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        if ( this.dialectIndex > 10 ) {
            return bufferIndex - start;
        }
        this.server.securityMode = buffer[ bufferIndex++ ] & 0xFF;
        this.server.security = this.server.securityMode & 0x01;
        this.server.encryptedPasswords = ( this.server.securityMode & 0x02 ) == 0x02;
        this.server.signaturesEnabled = ( this.server.securityMode & 0x04 ) == 0x04;
        this.server.signaturesRequired = ( this.server.securityMode & 0x08 ) == 0x08;
        this.server.smaxMpxCount = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.server.maxNumberVcs = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.server.maxBufferSize = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.server.maxRawSize = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.server.sessKey = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.server.scapabilities = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.server.serverTime = SMBUtil.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        int tzOffset = SMBUtil.readInt2(buffer, bufferIndex);
        // tzOffset is signed!
        if ( tzOffset > Short.MAX_VALUE ) {
            tzOffset = -1 * ( 65536 - tzOffset );
        }
        this.server.serverTimeZone = tzOffset;
        bufferIndex += 2;
        this.server.encryptionKeyLength = buffer[ bufferIndex++ ] & 0xFF;

        return bufferIndex - start;
    }


    @Override
    protected int readBytesWireFormat ( byte[] buffer, int bufferIndex ) {
        int start = bufferIndex;

        if ( ( this.server.scapabilities & SmbConstants.CAP_EXTENDED_SECURITY ) == 0 ) {
            this.server.encryptionKey = new byte[this.server.encryptionKeyLength];
            System.arraycopy(buffer, bufferIndex, this.server.encryptionKey, 0, this.server.encryptionKeyLength);
            bufferIndex += this.server.encryptionKeyLength;
            if ( this.byteCount > this.server.encryptionKeyLength ) {
                int len = 0;
                if ( ( this.negotiatedFlags2 & SmbConstants.FLAGS2_UNICODE ) == SmbConstants.FLAGS2_UNICODE ) {
                    len = Strings.findUNITermination(buffer, bufferIndex, 256);
                    this.server.oemDomainName = Strings.fromUNIBytes(buffer, bufferIndex, len);
                }
                else {
                    len = Strings.findTermination(buffer, bufferIndex, 256);
                    this.server.oemDomainName = Strings.fromOEMBytes(buffer, bufferIndex, len, getConfig());
                }
                bufferIndex += len;
            }
            else {
                this.server.oemDomainName = new String();
            }
        }
        else {
            this.server.guid = new byte[16];
            System.arraycopy(buffer, bufferIndex, this.server.guid, 0, 16);
            bufferIndex += this.server.guid.length;
            this.server.oemDomainName = new String();

            if ( this.byteCount > 16 ) {
                // have initial spnego token
                this.server.encryptionKeyLength = this.byteCount - 16;
                this.server.encryptionKey = new byte[this.server.encryptionKeyLength];
                System.arraycopy(buffer, bufferIndex, this.server.encryptionKey, 0, this.server.encryptionKeyLength);
                if ( log.isDebugEnabled() ) {
                    log.debug(
                        String.format("Have initial token %s", Hexdump.toHexString(this.server.encryptionKey, 0, this.server.encryptionKeyLength)));
                }
            }
        }

        return bufferIndex - start;
    }


    @Override
    public String toString () {
        return new String(
            "SmbComNegotiateResponse[" + super.toString() + ",wordCount=" + this.wordCount + ",dialectIndex=" + this.dialectIndex + ",securityMode=0x"
                    + Hexdump.toHexString(this.server.securityMode, 1) + ",security="
                    + ( this.server.security == SmbConstants.SECURITY_SHARE ? "share" : "user" ) + ",encryptedPasswords="
                    + this.server.encryptedPasswords + ",maxMpxCount=" + this.server.smaxMpxCount + ",maxNumberVcs=" + this.server.maxNumberVcs
                    + ",maxBufferSize=" + this.server.maxBufferSize + ",maxRawSize=" + this.server.maxRawSize + ",sessionKey=0x"
                    + Hexdump.toHexString(this.server.sessKey, 8) + ",capabilities=0x" + Hexdump.toHexString(this.server.scapabilities, 8)
                    + ",serverTime=" + new Date(this.server.serverTime) + ",serverTimeZone=" + this.server.serverTimeZone + ",encryptionKeyLength="
                    + this.server.encryptionKeyLength + ",byteCount=" + this.byteCount + ",oemDomainName=" + this.server.oemDomainName + "]");
    }

}
