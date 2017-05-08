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


@SuppressWarnings ( "javadoc" )
public class PacSignature {

    public static final int KERB_CHECKSUM_HMAC_MD5 = 0xFFFFFF76;
    public static final int HMAC_SHA1_96_AES128 = 0x0000000F;
    public static final int HMAC_SHA1_96_AES256 = 0x00000010;

    public static final int ETYPE_ARCFOUR_HMAC = 23;
    public static final int ETYPE_AES128_CTS_HMAC_SHA1_96 = 17;
    public static final int ETYPE_AES256_CTS_HMAC_SHA1_96 = 18;

    private int type;
    private byte[] checksum;


    public PacSignature ( byte[] data ) throws PACDecodingException {
        try {
            PacDataInputStream bufferStream = new PacDataInputStream(new DataInputStream(new ByteArrayInputStream(data)));
            this.type = bufferStream.readInt();
            switch ( this.type ) {
            case KERB_CHECKSUM_HMAC_MD5:
                this.checksum = new byte[16];
                break;
            case HMAC_SHA1_96_AES128:
            case HMAC_SHA1_96_AES256:
                this.checksum = new byte[12];
                break;
            default:
                this.checksum = new byte[bufferStream.available()];
                break;
            }
            bufferStream.readFully(this.checksum);
        }
        catch ( IOException e ) {
            throw new PACDecodingException("Malformed PAC signature", e);
        }
    }


    public int getType () {
        return this.type;
    }


    public byte[] getChecksum () {
        return this.checksum;
    }

}
