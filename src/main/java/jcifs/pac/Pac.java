/*
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
package jcifs.pac;


import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.Map;

import javax.security.auth.kerberos.KerberosKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.util.Hexdump;


@SuppressWarnings ( "javadoc" )
public class Pac {

    private static final Logger log = LoggerFactory.getLogger(Pac.class);

    private PacLogonInfo logonInfo;
    private PacCredentialType credentialType;
    private PacSignature serverSignature;
    private PacSignature kdcSignature;


    public Pac ( byte[] data, Map<Integer, KerberosKey> keys ) throws PACDecodingException {
        byte[] checksumData = data.clone();
        try {
            PacDataInputStream pacStream = new PacDataInputStream(new DataInputStream(new ByteArrayInputStream(data)));

            if ( data.length <= 8 )
                throw new PACDecodingException("Empty PAC");

            int bufferCount = pacStream.readInt();
            int version = pacStream.readInt();

            if ( version != PacConstants.PAC_VERSION ) {
                throw new PACDecodingException("Unrecognized PAC version " + version);
            }

            for ( int bufferIndex = 0; bufferIndex < bufferCount; bufferIndex++ ) {
                int bufferType = pacStream.readInt();
                int bufferSize = pacStream.readInt();
                long bufferOffset = pacStream.readLong();

                if ( bufferOffset % 8 != 0 ) {
                    throw new PACDecodingException("Unaligned buffer " + bufferType);
                }

                byte[] bufferData = new byte[bufferSize];
                System.arraycopy(data, (int) bufferOffset, bufferData, 0, bufferSize);

                switch ( bufferType ) {
                case PacConstants.LOGON_INFO:
                    // PAC Credential Information
                    if ( this.logonInfo == null ) {
                        this.logonInfo = new PacLogonInfo(bufferData);
                    }
                    break;
                case PacConstants.CREDENTIAL_TYPE:
                    // PAC Credential Type
                    this.credentialType = new PacCredentialType(bufferData);
                    break;
                case PacConstants.SERVER_CHECKSUM:
                    // PAC Server Signature
                    if ( this.serverSignature == null ) {
                        this.serverSignature = new PacSignature(bufferData);
                        if ( log.isDebugEnabled() ) {
                            log.debug(
                                String.format("Server signature is type %d @ %d len %d", this.serverSignature.getType(), bufferOffset, bufferSize));
                        }
                        // Clear signature from checksum copy
                        for ( int i = 0; i < this.serverSignature.getChecksum().length; i++ )
                            checksumData[ (int) bufferOffset + 4 + i ] = 0;
                    }
                    break;
                case PacConstants.PRIVSVR_CHECKSUM:
                    // PAC KDC Signature
                    if ( this.kdcSignature == null ) {
                        this.kdcSignature = new PacSignature(bufferData);
                        if ( log.isDebugEnabled() ) {
                            log.debug(String.format("KDC signature is type %d @ %d len %d", this.kdcSignature.getType(), bufferOffset, bufferSize));
                        }
                        // Clear signature from checksum copy
                        for ( int i = 0; i < this.kdcSignature.getChecksum().length; i++ )
                            checksumData[ (int) bufferOffset + 4 + i ] = 0;
                    }
                    break;
                default:
                    if ( log.isDebugEnabled() ) {
                        log.debug("Found unhandled PAC buffer " + bufferType);
                    }
                }
            }
        }
        catch ( IOException e ) {
            throw new PACDecodingException("Malformed PAC", e);
        }

        if ( this.serverSignature == null || this.kdcSignature == null || this.logonInfo == null ) {
            throw new PACDecodingException("Missing required buffers");
        }

        if ( log.isTraceEnabled() ) {
            log.trace(
                String.format(
                    "Checksum data %s type %d signature %s",
                    Hexdump.toHexString(checksumData),
                    this.serverSignature.getType(),
                    Hexdump.toHexString(this.serverSignature.getChecksum())));
        }

        byte checksum[] = PacMac.calculateMac(this.serverSignature.getType(), keys, checksumData);
        if ( !MessageDigest.isEqual(this.serverSignature.getChecksum(), checksum) ) {
            if ( log.isDebugEnabled() ) {
                log.debug(
                    String.format(
                        "PAC signature validation failed, have: %s expected: %s type: %d len: %d",
                        Hexdump.toHexString(checksum),
                        Hexdump.toHexString(this.serverSignature.getChecksum()),
                        this.serverSignature.getType(),
                        data.length));
            }
            if ( log.isTraceEnabled() ) {
                log.trace(String.format("Checksum data %s", Hexdump.toHexString(checksumData)));
            }
            throw new PACDecodingException("Invalid PAC signature");
        }
    }


    public PacLogonInfo getLogonInfo () {
        return this.logonInfo;
    }


    public PacCredentialType getCredentialType () {
        return this.credentialType;
    }


    public PacSignature getServerSignature () {
        return this.serverSignature;
    }


    public PacSignature getKdcSignature () {
        return this.kdcSignature;
    }
}
