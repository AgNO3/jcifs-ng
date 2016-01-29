package jcifs.pac.kerberos;


import java.io.ByteArrayInputStream;
import java.io.IOException;

import javax.security.auth.kerberos.KerberosKey;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERApplicationSpecific;

import jcifs.pac.PACDecodingException;
import jcifs.util.ASN1Util;


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
