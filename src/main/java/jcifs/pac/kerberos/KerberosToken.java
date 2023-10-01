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

import org.bouncycastle.asn1.*;

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

        byte[] content;
        try ( ASN1InputStream stream = new ASN1InputStream(token) ) {
            content = ASN1Util.readUnparsedTagged(0, 0x8000, stream);
        }catch ( IOException e ) {
            throw new PACDecodingException("Malformed kerberos token", e);
        }

        try ( ASN1InputStream stream = new ASN1InputStream(content) ) {

            ASN1ObjectIdentifier kerberosOid = (ASN1ObjectIdentifier) stream.readObject();
            if ( !kerberosOid.getId().equals(KerberosConstants.KERBEROS_OID) )
                throw new PACDecodingException("Not a kerberos token");


            // yes, there really is non ASN.1/DER data inside the tagged object
            int read = 0;
            int readLow = stream.read() & 0xff;
            int readHigh = stream.read() & 0xff;
            read = ( readHigh << 8 ) + readLow;
            if ( read != 0x01 )
                throw new PACDecodingException("Malformed kerberos token");

            ASN1TaggedObject mechToken = ASN1Util.as(ASN1TaggedObject.class, stream.readObject());
            if ( mechToken == null || mechToken.getTagClass() != BERTags.APPLICATION ||
                    !(mechToken.getBaseObject() instanceof ASN1Sequence) )
                throw new PACDecodingException("Malformed kerberos token");

            this.apRequest = new KerberosApRequest((ASN1Sequence) mechToken.getBaseObject(), keys);
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
