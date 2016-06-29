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


import java.util.Date;

import org.apache.log4j.Logger;

import jcifs.Configuration;
import jcifs.SmbConstants;
import jcifs.util.Hexdump;
import jcifs.util.Strings;


class SmbComNegotiateResponse extends ServerMessageBlock {

    private static final Logger log = Logger.getLogger(SmbComNegotiateResponse.class);

    int dialectIndex;
    SmbTransport.ServerData server;


    SmbComNegotiateResponse ( Configuration config, SmbTransport.ServerData server ) {
        super(config);
        this.server = server;
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
    int readBytesWireFormat ( byte[] buffer, int bufferIndex ) {
        int start = bufferIndex;

        if ( ( this.server.scapabilities & SmbConstants.CAP_EXTENDED_SECURITY ) == 0 ) {
            this.server.encryptionKey = new byte[this.server.encryptionKeyLength];
            System.arraycopy(buffer, bufferIndex, this.server.encryptionKey, 0, this.server.encryptionKeyLength);
            bufferIndex += this.server.encryptionKeyLength;
            if ( this.byteCount > this.server.encryptionKeyLength ) {
                int len = 0;
                if ( ( this.flags2 & SmbConstants.FLAGS2_UNICODE ) == SmbConstants.FLAGS2_UNICODE ) {
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
