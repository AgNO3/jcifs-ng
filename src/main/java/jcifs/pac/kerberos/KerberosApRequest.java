package jcifs.pac.kerberos;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Enumeration;

import javax.security.auth.kerberos.KerberosKey;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DLSequence;

import jcifs.pac.PACDecodingException;
import jcifs.util.ASN1Util;


public class KerberosApRequest {

    private byte apOptions;
    private KerberosTicket ticket;


    public KerberosApRequest ( byte[] token, KerberosKey[] keys ) throws PACDecodingException {
        if ( token.length <= 0 )
            throw new PACDecodingException("Empty kerberos ApReq");

        DLSequence sequence;
        try {
            try ( ASN1InputStream stream = new ASN1InputStream(new ByteArrayInputStream(token)) ) {
                sequence = ASN1Util.as(DLSequence.class, stream);
            }
        }
        catch ( IOException e ) {
            throw new PACDecodingException("Malformed Kerberos Ticket", e);
        }

        Enumeration<?> fields = sequence.getObjects();
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
                DERApplicationSpecific derTicket = ASN1Util.as(DERApplicationSpecific.class, tagged);
                if ( !derTicket.isConstructed() )
                    throw new PACDecodingException("Malformed Kerberos Ticket");
                this.ticket = new KerberosTicket(derTicket.getContents(), this.apOptions, keys);
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
