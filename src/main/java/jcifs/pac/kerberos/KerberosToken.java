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
package jcifs.pac.kerberos;


import java.io.ByteArrayInputStream;
import java.io.IOException;

import javax.security.auth.kerberos.KerberosKey;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERApplicationSpecific;

import jcifs.pac.ASN1Util;
import jcifs.pac.PACDecodingException;


@SuppressWarnings ( "javadoc" )
public class KerberosToken {

    private KerberosApRequest apRequest;


    public KerberosToken ( byte[] token ) throws PACDecodingException {
        this(token, null);
    }


    public KerberosToken ( byte[] token, KerberosKey[] keys ) throws PACDecodingException {

        if ( token.length <= 0 )
            throw new PACDecodingException("Empty kerberos token");

        try {
            ASN1InputStream stream = new ASN1InputStream(new ByteArrayInputStream(token));
            DERApplicationSpecific derToken = ASN1Util.as(DERApplicationSpecific.class, stream);
            if ( derToken == null || !derToken.isConstructed() )
                throw new PACDecodingException("Malformed kerberos token");
            stream.close();

            stream = new ASN1InputStream(new ByteArrayInputStream(derToken.getContents()));
            ASN1ObjectIdentifier kerberosOid = ASN1Util.as(ASN1ObjectIdentifier.class, stream);
            if ( !kerberosOid.getId().equals(KerberosConstants.KERBEROS_OID) )
                throw new PACDecodingException("Not a kerberos token");

            int read = 0;
            int readLow = stream.read() & 0xff;
            int readHigh = stream.read() & 0xff;
            read = ( readHigh << 8 ) + readLow;
            if ( read != 0x01 )
                throw new PACDecodingException("Malformed kerberos token");

            DERApplicationSpecific krbToken = ASN1Util.as(DERApplicationSpecific.class, stream);
            if ( krbToken == null || !krbToken.isConstructed() )
                throw new PACDecodingException("Malformed kerberos token");

            stream.close();

            this.apRequest = new KerberosApRequest(krbToken.getContents(), keys);
        }
        catch ( IOException e ) {
            throw new PACDecodingException("Malformed kerberos token", e);
        }
    }


    public KerberosTicket getTicket () {
        return this.apRequest.getTicket();
    }


    public KerberosApRequest getApRequest () {
        return this.apRequest;
    }

}
