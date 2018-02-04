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


import java.security.GeneralSecurityException;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.SmbConstants;
import jcifs.internal.smb1.AndXServerMessageBlock;
import jcifs.internal.smb1.ServerMessageBlock;
import jcifs.internal.util.SMBUtil;
import jcifs.smb.NtlmPasswordAuthenticator;
import jcifs.smb.SmbException;


/**
 * 
 */
public class SmbComSessionSetupAndX extends AndXServerMessageBlock {

    private byte[] lmHash, ntHash, blob = null;
    private String accountName, primaryDomain;
    private SmbComNegotiateResponse negotiated;
    private int capabilities;


    /**
     * 
     * @param tc
     * @param negotiated
     * @param andx
     * @param cred
     * @throws SmbException
     * @throws GeneralSecurityException
     */
    public SmbComSessionSetupAndX ( CIFSContext tc, SmbComNegotiateResponse negotiated, ServerMessageBlock andx, Object cred )
            throws SmbException, GeneralSecurityException {
        super(tc.getConfig(), SMB_COM_SESSION_SETUP_ANDX, andx);
        this.negotiated = negotiated;
        this.capabilities = negotiated.getNegotiatedCapabilities();
        ServerData server = negotiated.getServerData();
        if ( server.security == SmbConstants.SECURITY_USER ) {
            if ( cred instanceof NtlmPasswordAuthenticator ) {
                NtlmPasswordAuthenticator a = (NtlmPasswordAuthenticator) cred;
                if ( a.isAnonymous() ) {
                    this.lmHash = new byte[0];
                    this.ntHash = new byte[0];
                    this.capabilities &= ~SmbConstants.CAP_EXTENDED_SECURITY;
                    if ( !a.isGuest() ) {
                        this.accountName = a.getUsername();
                        if ( this.isUseUnicode() )
                            this.accountName = this.accountName.toUpperCase();
                        this.primaryDomain = a.getUserDomain() != null ? a.getUserDomain().toUpperCase() : "?";
                    }
                    else {
                        this.accountName = "";
                        this.primaryDomain = "";
                    }
                }
                else {
                    this.accountName = a.getUsername();
                    if ( this.isUseUnicode() )
                        this.accountName = this.accountName.toUpperCase();
                    this.primaryDomain = a.getUserDomain() != null ? a.getUserDomain().toUpperCase() : "?";
                    if ( server.encryptedPasswords ) {
                        this.lmHash = a.getAnsiHash(tc, server.encryptionKey);
                        this.ntHash = a.getUnicodeHash(tc, server.encryptionKey);
                        // prohibit HTTP auth attempts for the null session
                        if ( this.lmHash.length == 0 && this.ntHash.length == 0 ) {
                            throw new RuntimeException("Null setup prohibited.");
                        }
                    }
                    else if ( tc.getConfig().isDisablePlainTextPasswords() ) {
                        throw new RuntimeException("Plain text passwords are disabled");
                    }
                    else {
                        // plain text
                        String password = a.getPassword();
                        this.lmHash = new byte[ ( password.length() + 1 ) * 2];
                        this.ntHash = new byte[0];
                        writeString(password, this.lmHash, 0);
                    }
                }

            }
            else if ( cred instanceof byte[] ) {
                this.blob = (byte[]) cred;
            }
            else {
                throw new SmbException("Unsupported credential type " + ( cred != null ? cred.getClass() : "NULL" ));
            }
        }
        else if ( server.security == SmbConstants.SECURITY_SHARE ) {
            if ( cred instanceof NtlmPasswordAuthenticator ) {
                NtlmPasswordAuthenticator a = (NtlmPasswordAuthenticator) cred;
                this.lmHash = new byte[0];
                this.ntHash = new byte[0];
                if ( !a.isAnonymous() ) {
                    this.accountName = a.getUsername();
                    if ( this.isUseUnicode() )
                        this.accountName = this.accountName.toUpperCase();
                    this.primaryDomain = a.getUserDomain() != null ? a.getUserDomain().toUpperCase() : "?";
                }
                else {
                    this.accountName = "";
                    this.primaryDomain = "";
                }
            }
            else {
                throw new SmbException("Unsupported credential type");
            }
        }
        else {
            throw new SmbException("Unsupported");
        }
    }


    @Override
    protected int getBatchLimit ( Configuration cfg, byte cmd ) {
        return cmd == SMB_COM_TREE_CONNECT_ANDX ? cfg.getBatchLimit("SessionSetupAndX.TreeConnectAndX") : 0;
    }


    @Override
    protected int writeParameterWordsWireFormat ( byte[] dst, int dstIndex ) {
        int start = dstIndex;

        SMBUtil.writeInt2(this.negotiated.getNegotiatedSendBufferSize(), dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt2(this.negotiated.getNegotiatedMpxCount(), dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt2(getConfig().getVcNumber(), dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt4(this.negotiated.getNegotiatedSessionKey(), dst, dstIndex);
        dstIndex += 4;
        if ( this.blob != null ) {
            SMBUtil.writeInt2(this.blob.length, dst, dstIndex);
            dstIndex += 2;
        }
        else {
            SMBUtil.writeInt2(this.lmHash.length, dst, dstIndex);
            dstIndex += 2;
            SMBUtil.writeInt2(this.ntHash.length, dst, dstIndex);
            dstIndex += 2;
        }
        dst[ dstIndex++ ] = (byte) 0x00;
        dst[ dstIndex++ ] = (byte) 0x00;
        dst[ dstIndex++ ] = (byte) 0x00;
        dst[ dstIndex++ ] = (byte) 0x00;
        SMBUtil.writeInt4(this.capabilities, dst, dstIndex);
        dstIndex += 4;

        return dstIndex - start;
    }


    @Override
    protected int writeBytesWireFormat ( byte[] dst, int dstIndex ) {
        int start = dstIndex;

        if ( this.blob != null ) {
            System.arraycopy(this.blob, 0, dst, dstIndex, this.blob.length);
            dstIndex += this.blob.length;
        }
        else {
            System.arraycopy(this.lmHash, 0, dst, dstIndex, this.lmHash.length);
            dstIndex += this.lmHash.length;
            System.arraycopy(this.ntHash, 0, dst, dstIndex, this.ntHash.length);
            dstIndex += this.ntHash.length;

            dstIndex += writeString(this.accountName, dst, dstIndex);
            dstIndex += writeString(this.primaryDomain, dst, dstIndex);
        }
        dstIndex += writeString(getConfig().getNativeOs(), dst, dstIndex);
        dstIndex += writeString(getConfig().getNativeLanman(), dst, dstIndex);

        return dstIndex - start;
    }


    @Override
    protected int readParameterWordsWireFormat ( byte[] buffer, int bufferIndex ) {
        return 0;
    }


    @Override
    protected int readBytesWireFormat ( byte[] buffer, int bufferIndex ) {
        return 0;
    }


    @Override
    public String toString () {
        String result = new String(
            "SmbComSessionSetupAndX[" + super.toString() + ",snd_buf_size=" + this.negotiated.getNegotiatedSendBufferSize() + ",maxMpxCount="
                    + this.negotiated.getNegotiatedMpxCount() + ",VC_NUMBER=" + getConfig().getVcNumber() + ",sessionKey="
                    + this.negotiated.getNegotiatedSessionKey() + ",lmHash.length=" + ( this.lmHash == null ? 0 : this.lmHash.length )
                    + ",ntHash.length=" + ( this.ntHash == null ? 0 : this.ntHash.length ) + ",capabilities=" + this.capabilities + ",accountName="
                    + this.accountName + ",primaryDomain=" + this.primaryDomain + ",NATIVE_OS=" + getConfig().getNativeOs() + ",NATIVE_LANMAN="
                    + getConfig().getNativeLanman() + "]");
        return result;
    }
}
