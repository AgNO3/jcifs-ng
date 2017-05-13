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


import jcifs.Configuration;
import jcifs.internal.smb1.AndXServerMessageBlock;
import jcifs.internal.smb1.ServerMessageBlock;
import jcifs.internal.util.SMBUtil;


/**
 * 
 */
public class SmbComSessionSetupAndXResponse extends AndXServerMessageBlock {

    private String nativeOs = "";
    private String nativeLanMan = "";
    private String primaryDomain = "";

    private boolean isLoggedInAsGuest;
    private byte[] blob = null;


    /**
     * 
     * @param config
     * @param andx
     */
    public SmbComSessionSetupAndXResponse ( Configuration config, ServerMessageBlock andx ) {
        super(config, andx);
    }


    /**
     * @return the nativeLanMan
     */
    public final String getNativeLanMan () {
        return this.nativeLanMan;
    }


    /**
     * @return the nativeOs
     */
    public final String getNativeOs () {
        return this.nativeOs;
    }


    /**
     * @return the primaryDomain
     */
    public final String getPrimaryDomain () {
        return this.primaryDomain;
    }


    /**
     * @return the isLoggedInAsGuest
     */
    public final boolean isLoggedInAsGuest () {
        return this.isLoggedInAsGuest;
    }


    /**
     * @return the blob
     */
    public final byte[] getBlob () {
        return this.blob;
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
        this.isLoggedInAsGuest = ( buffer[ bufferIndex ] & 0x01 ) == 0x01 ? true : false;
        bufferIndex += 2;
        if ( this.isExtendedSecurity() ) {
            int blobLength = SMBUtil.readInt2(buffer, bufferIndex);
            bufferIndex += 2;
            this.blob = new byte[blobLength];
        }
        return bufferIndex - start;
    }


    @Override
    protected int readBytesWireFormat ( byte[] buffer, int bufferIndex ) {
        int start = bufferIndex;

        if ( this.isExtendedSecurity() ) {
            System.arraycopy(buffer, bufferIndex, this.blob, 0, this.blob.length);
            bufferIndex += this.blob.length;
        }

        this.nativeOs = readString(buffer, bufferIndex);
        bufferIndex += stringWireLength(this.nativeOs, bufferIndex);
        this.nativeLanMan = readString(buffer, bufferIndex, start + this.byteCount, 255, this.isUseUnicode());
        bufferIndex += stringWireLength(this.nativeLanMan, bufferIndex);
        if ( !this.isExtendedSecurity() ) {
            this.primaryDomain = readString(buffer, bufferIndex, start + this.byteCount, 255, this.isUseUnicode());
            bufferIndex += stringWireLength(this.primaryDomain, bufferIndex);
        }

        return bufferIndex - start;
    }


    @Override
    public String toString () {
        String result = new String(
            "SmbComSessionSetupAndXResponse[" + super.toString() + ",isLoggedInAsGuest=" + this.isLoggedInAsGuest + ",nativeOs=" + this.nativeOs
                    + ",nativeLanMan=" + this.nativeLanMan + ",primaryDomain=" + this.primaryDomain + "]");
        return result;
    }
}
