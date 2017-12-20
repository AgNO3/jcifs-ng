/* jcifs smb client library in Java
 * Copyright (C) 2004  "Michael B. Allen" <jcifs at samba dot org>
 *                   "Eric Glass" <jcifs at samba dot org>
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

package jcifs.spnego;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;


@SuppressWarnings ( "javadoc" )
public class NegTokenTarg extends SpnegoToken {

    public static final int UNSPECIFIED_RESULT = -1;
    public static final int ACCEPT_COMPLETED = 0;
    public static final int ACCEPT_INCOMPLETE = 1;
    public static final int REJECTED = 2;
    public static final int REQUEST_MIC = 3;

    private ASN1ObjectIdentifier mechanism;

    private int result = UNSPECIFIED_RESULT;


    public NegTokenTarg () {}


    public NegTokenTarg ( int result, ASN1ObjectIdentifier mechanism, byte[] mechanismToken, byte[] mechanismListMIC ) {
        setResult(result);
        setMechanism(mechanism);
        setMechanismToken(mechanismToken);
        setMechanismListMIC(mechanismListMIC);
    }


    public NegTokenTarg ( byte[] token ) throws IOException {
        parse(token);
    }


    public int getResult () {
        return this.result;
    }


    public void setResult ( int result ) {
        this.result = result;
    }


    public ASN1ObjectIdentifier getMechanism () {
        return this.mechanism;
    }


    public void setMechanism ( ASN1ObjectIdentifier mechanism ) {
        this.mechanism = mechanism;
    }


    @Override
    public byte[] toByteArray () {
        try {
            ByteArrayOutputStream collector = new ByteArrayOutputStream();
            DEROutputStream der = new DEROutputStream(collector);
            ASN1EncodableVector fields = new ASN1EncodableVector();
            int res = getResult();
            if ( res != UNSPECIFIED_RESULT ) {
                fields.add(new DERTaggedObject(true, 0, new ASN1Enumerated(res)));
            }
            ASN1ObjectIdentifier mech = getMechanism();
            if ( mech != null ) {
                fields.add(new DERTaggedObject(true, 1, mech));
            }
            byte[] mechanismToken = getMechanismToken();
            if ( mechanismToken != null ) {
                fields.add(new DERTaggedObject(true, 2, new DEROctetString(mechanismToken)));
            }
            byte[] mechanismListMIC = getMechanismListMIC();
            if ( mechanismListMIC != null ) {
                fields.add(new DERTaggedObject(true, 3, new DEROctetString(mechanismListMIC)));
            }
            der.writeObject(new DERTaggedObject(true, 1, new DERSequence(fields)));
            return collector.toByteArray();
        }
        catch ( IOException ex ) {
            throw new IllegalStateException(ex.getMessage());
        }
    }


    @Override
    protected void parse ( byte[] token ) throws IOException {
        try ( ASN1InputStream der = new ASN1InputStream(token) ) {
            ASN1TaggedObject tagged = (ASN1TaggedObject) der.readObject();
            ASN1Sequence sequence = ASN1Sequence.getInstance(tagged, true);
            Enumeration<?> fields = sequence.getObjects();
            while ( fields.hasMoreElements() ) {
                tagged = (ASN1TaggedObject) fields.nextElement();
                switch ( tagged.getTagNo() ) {
                case 0:
                    ASN1Enumerated enumerated = ASN1Enumerated.getInstance(tagged, true);
                    setResult(enumerated.getValue().intValue());
                    break;
                case 1:
                    setMechanism(ASN1ObjectIdentifier.getInstance(tagged, true));
                    break;
                case 2:
                    ASN1OctetString mechanismToken = ASN1OctetString.getInstance(tagged, true);
                    setMechanismToken(mechanismToken.getOctets());
                    break;
                case 3:
                    ASN1OctetString mechanismListMIC = ASN1OctetString.getInstance(tagged, true);
                    setMechanismListMIC(mechanismListMIC.getOctets());
                    break;
                default:
                    throw new IOException("Malformed token field.");
                }
            }
        }
    }

}
