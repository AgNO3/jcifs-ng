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
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

import javax.security.auth.kerberos.KerberosKey;

import org.bouncycastle.asn1.*;

import jcifs.pac.ASN1Util;
import jcifs.pac.PACDecodingException;


@SuppressWarnings ( "javadoc" )
public class KerberosRelevantAuthData extends KerberosAuthData {

    private List<KerberosAuthData> authorizations;


    public KerberosRelevantAuthData ( byte[] token, Map<Integer, KerberosKey> keys ) throws PACDecodingException {
        ASN1Sequence authSequence;
        try {
            try ( ASN1InputStream stream = new ASN1InputStream(new ByteArrayInputStream(token)) ) {
                authSequence = ASN1Util.as(ASN1Sequence.class, stream);
            }
        }
        catch ( IOException e ) {
            throw new PACDecodingException("Malformed kerberos ticket", e);
        }

        this.authorizations = new ArrayList<>();
        Enumeration<?> authElements = authSequence.getObjects();
        while ( authElements.hasMoreElements() ) {
            ASN1Sequence authElement = ASN1Util.as(ASN1Sequence.class, authElements);
            ASN1Integer authType = ASN1Util.as(ASN1Integer.class, ASN1Util.as(ASN1TaggedObject.class, authElement, 0));
            DEROctetString authData = ASN1Util.as(DEROctetString.class, ASN1Util.as(ASN1TaggedObject.class, authElement, 1));

            this.authorizations.addAll(KerberosAuthData.parse(authType.getValue().intValue(), authData.getOctets(), keys));
        }
    }


    public List<KerberosAuthData> getAuthorizations () {
        return this.authorizations;
    }

}
