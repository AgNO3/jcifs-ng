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
import java.math.BigInteger;
import java.util.Enumeration;

import javax.security.auth.kerberos.KerberosKey;

import org.bouncycastle.asn1.*;

import jcifs.pac.ASN1Util;
import jcifs.pac.PACDecodingException;


@SuppressWarnings ( "javadoc" )
public class KerberosApRequest {

    private byte apOptions;
    private KerberosTicket ticket;


    public KerberosApRequest ( byte[] token, KerberosKey[] keys ) throws PACDecodingException {
        this(parseSequence(token), keys);
    }

    private static ASN1Sequence parseSequence(byte[] token) throws PACDecodingException {
        if ( token.length <= 0 )
            throw new PACDecodingException("Empty kerberos ApReq");

        ASN1Sequence sequence;
        try {
            try ( ASN1InputStream stream = new ASN1InputStream(new ByteArrayInputStream(token)) ) {
                sequence = ASN1Util.as(ASN1Sequence.class, stream);
            }
        }
        catch ( IOException e ) {
            throw new PACDecodingException("Malformed Kerberos Ticket", e);
        }
        return sequence;
    }

    public KerberosApRequest(ASN1Sequence seq, KerberosKey[] keys) throws PACDecodingException {
        Enumeration<?> fields = seq.getObjects();
        while ( fields.hasMoreElements() ) {
            ASN1TaggedObject tagged = ASN1Util.as(ASN1TaggedObject.class, fields.nextElement());
            switch ( tagged.getTagNo() ) {
            case 0:
                ASN1Integer pvno = ASN1Util.as(ASN1Integer.class, tagged);
                if ( !pvno.getValue().equals(new BigInteger(KerberosConstants.KERBEROS_VERSION)) ) {
                    throw new PACDecodingException("Invalid kerberos version");
                }
                break;
            case 1:
                ASN1Integer msgType = ASN1Util.as(ASN1Integer.class, tagged);
                if ( !msgType.getValue().equals(new BigInteger(KerberosConstants.KERBEROS_AP_REQ)) )
                    throw new PACDecodingException("Invalid kerberos request");
                break;
            case 2:
                DERBitString bitString = ASN1Util.as(DERBitString.class, tagged);
                this.apOptions = bitString.getBytes()[ 0 ];
                break;
            case 3:
                ASN1TaggedObject derTicket = ASN1Util.as(ASN1TaggedObject.class, tagged);
                if ( derTicket.getTagClass() != BERTags.APPLICATION )
                    throw new PACDecodingException("Malformed Kerberos Ticket");
                try {
                    this.ticket = new KerberosTicket(derTicket.getBaseObject().getEncoded(), this.apOptions, keys);
                } catch (IOException e) {
                    throw new PACDecodingException("Malformed Kerberos Ticket", e);
                }
                break;
            case 4:
                // Let's ignore this for now
                break;
            default:
                throw new PACDecodingException("Invalid field in kerberos ticket");
            }
        }
    }


    public byte getApOptions () {
        return this.apOptions;
    }


    public KerberosTicket getTicket () {
        return this.ticket;
    }
}
