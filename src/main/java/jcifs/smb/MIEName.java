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
package jcifs.smb;


import java.util.Objects;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;


/**
 * This class is used to parse the name of context initiator and
 * context acceptor which are retrieved from GSSContext.
 * 
 * @author Shun
 *
 */
class MIEName {

    private static byte[] TOK_ID = {
        04, 01
    };
    private static int TOK_ID_SIZE = 2;
    private static int MECH_OID_LEN_SIZE = 2;
    private static int NAME_LEN_SIZE = 4;

    private ASN1ObjectIdentifier oid;
    private String name;


    /**
     * Instance a <code>MIEName</code> object.
     * 
     * @param buf
     *            the name of context initiator or acceptor
     */
    MIEName ( byte[] buf ) {
        int i;
        int len;
        if ( buf.length < TOK_ID_SIZE + MECH_OID_LEN_SIZE ) {
            throw new IllegalArgumentException();
        }
        // TOK_ID
        for ( i = 0; i < TOK_ID.length; i++ ) {
            if ( TOK_ID[ i ] != buf[ i ] ) {
                throw new IllegalArgumentException();
            }
        }
        // MECH_OID_LEN
        len = 0xff00 & ( buf[ i++ ] << 8 );
        len |= 0xff & buf[ i++ ];

        // MECH_OID
        if ( buf.length < i + len ) {
            throw new IllegalArgumentException();
        }
        byte[] bo = new byte[len];
        System.arraycopy(buf, i, bo, 0, len);
        i += len;
        this.oid = ASN1ObjectIdentifier.getInstance(bo);

        // NAME_LEN
        if ( buf.length < i + NAME_LEN_SIZE ) {
            throw new IllegalArgumentException();
        }
        len = 0xff000000 & ( buf[ i++ ] << 24 );
        len |= 0x00ff0000 & ( buf[ i++ ] << 16 );
        len |= 0x0000ff00 & ( buf[ i++ ] << 8 );
        len |= 0x000000ff & buf[ i++ ];

        // NAME
        if ( buf.length < i + len ) {
            throw new IllegalArgumentException();
        }
        this.name = new String(buf, i, len);

    }


    MIEName ( ASN1ObjectIdentifier oid, String name ) {
        this.oid = oid;
        this.name = name;
    }


    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals ( Object other ) {

        if ( other instanceof MIEName ) {
            MIEName terg = (MIEName) other;
            if ( Objects.equals(this.oid, terg.oid)
                    && ( ( this.name == null && terg.name == null ) || ( this.name != null && this.name.equalsIgnoreCase(terg.name) ) ) ) {
                return true;
            }
        }
        return false;
    }


    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode () {
        return this.oid.hashCode();
    }


    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString () {
        return this.name;
    }
}
