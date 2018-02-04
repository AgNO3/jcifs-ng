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


import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.RuntimeCIFSException;
import jcifs.SmbConstants;
import jcifs.internal.smb1.AndXServerMessageBlock;
import jcifs.internal.smb1.ServerMessageBlock;
import jcifs.internal.util.SMBUtil;
import jcifs.smb.NtlmPasswordAuthenticator;
import jcifs.util.Hexdump;


/**
 * 
 */
public class SmbComTreeConnectAndX extends AndXServerMessageBlock {

    private boolean disconnectTid = false;
    private String service;
    private byte[] password;
    private int passwordLength;
    private CIFSContext ctx;
    private ServerData server;


    /**
     * 
     * @param ctx
     * @param server
     * @param path
     * @param service
     * @param andx
     */
    public SmbComTreeConnectAndX ( CIFSContext ctx, ServerData server, String path, String service, ServerMessageBlock andx ) {
        super(ctx.getConfig(), SMB_COM_TREE_CONNECT_ANDX, andx);
        this.ctx = ctx;
        this.server = server;
        this.path = path;
        this.service = service;
    }


    @Override
    protected int getBatchLimit ( Configuration cfg, byte cmd ) {
        int c = cmd & 0xFF;
        switch ( c ) {
        case SMB_COM_CHECK_DIRECTORY:
            return cfg.getBatchLimit("TreeConnectAndX.CheckDirectory");
        case SMB_COM_CREATE_DIRECTORY:
            return cfg.getBatchLimit("TreeConnectAndX.CreateDirectory");
        case SMB_COM_DELETE:
            return cfg.getBatchLimit("TreeConnectAndX.Delete");
        case SMB_COM_DELETE_DIRECTORY:
            return cfg.getBatchLimit("TreeConnectAndX.DeleteDirectory");
        case SMB_COM_OPEN_ANDX:
            return cfg.getBatchLimit("TreeConnectAndX.OpenAndX");
        case SMB_COM_RENAME:
            return cfg.getBatchLimit("TreeConnectAndX.Rename");
        case SMB_COM_TRANSACTION:
            return cfg.getBatchLimit("TreeConnectAndX.Transaction");
        case SMB_COM_QUERY_INFORMATION:
            return cfg.getBatchLimit("TreeConnectAndX.QueryInformation");
        }
        return 0;
    }


    @Override
    protected int writeParameterWordsWireFormat ( byte[] dst, int dstIndex ) {
        if ( this.server.security == SmbConstants.SECURITY_SHARE && this.ctx.getCredentials() instanceof NtlmPasswordAuthenticator ) {
            NtlmPasswordAuthenticator pwAuth = (NtlmPasswordAuthenticator) this.ctx.getCredentials();
            if ( isExternalAuth(pwAuth) ) {
                this.passwordLength = 1;
            }
            else if ( this.server.encryptedPasswords ) {
                // encrypted
                try {
                    this.password = pwAuth.getAnsiHash(this.ctx, this.server.encryptionKey);
                }
                catch ( GeneralSecurityException e ) {
                    throw new RuntimeCIFSException("Failed to encrypt password", e);
                }
                this.passwordLength = this.password.length;
            }
            else if ( this.ctx.getConfig().isDisablePlainTextPasswords() ) {
                throw new RuntimeCIFSException("Plain text passwords are disabled");
            }
            else {
                // plain text
                this.password = new byte[ ( pwAuth.getPassword().length() + 1 ) * 2];
                this.passwordLength = writeString(pwAuth.getPassword(), this.password, 0);
            }
        }
        else {
            // no password in tree connect
            this.passwordLength = 1;
        }

        dst[ dstIndex++ ] = this.disconnectTid ? (byte) 0x01 : (byte) 0x00;
        dst[ dstIndex++ ] = (byte) 0x00;
        SMBUtil.writeInt2(this.passwordLength, dst, dstIndex);
        return 4;
    }


    @SuppressWarnings ( "deprecation" )
    private static boolean isExternalAuth ( NtlmPasswordAuthenticator pwAuth ) {
        return pwAuth instanceof jcifs.smb.NtlmPasswordAuthentication && ! ( (jcifs.smb.NtlmPasswordAuthentication) pwAuth ).areHashesExternal()
                && pwAuth.getPassword().isEmpty();
    }


    @Override
    protected int writeBytesWireFormat ( byte[] dst, int dstIndex ) {
        int start = dstIndex;
        if ( this.server.security == SmbConstants.SECURITY_SHARE && this.ctx.getCredentials() instanceof NtlmPasswordAuthenticator ) {
            NtlmPasswordAuthenticator pwAuth = (NtlmPasswordAuthenticator) this.ctx.getCredentials();
            if ( isExternalAuth(pwAuth) ) {
                dst[ dstIndex++ ] = (byte) 0x00;
            }
            else {
                System.arraycopy(this.password, 0, dst, dstIndex, this.passwordLength);
                dstIndex += this.passwordLength;
            }
        }
        else {
            // no password in tree connect
            dst[ dstIndex++ ] = (byte) 0x00;
        }
        dstIndex += writeString(this.path, dst, dstIndex);
        try {
            System.arraycopy(this.service.getBytes("ASCII"), 0, dst, dstIndex, this.service.length());
        }
        catch ( UnsupportedEncodingException uee ) {
            return 0;
        }
        dstIndex += this.service.length();
        dst[ dstIndex++ ] = (byte) '\0';

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
            "SmbComTreeConnectAndX[" + super.toString() + ",disconnectTid=" + this.disconnectTid + ",passwordLength=" + this.passwordLength
                    + ",password=" + Hexdump.toHexString(this.password, this.passwordLength, 0) + ",path=" + this.path + ",service=" + this.service
                    + "]");
        return result;
    }
}
