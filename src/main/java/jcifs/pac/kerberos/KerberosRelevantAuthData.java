package jcifs.pac.kerberos;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Key;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSequence;

import jcifs.pac.PACDecodingException;
import jcifs.util.ASN1Util;


public class KerberosRelevantAuthData extends KerberosAuthData {

    private List<KerberosAuthData> authorizations;


    public KerberosRelevantAuthData ( byte[] token, Key key ) throws PACDecodingException {
        DLSequence authSequence;
        try {
            try ( ASN1InputStream stream = new ASN1InputStream(new ByteArrayInputStream(token)) ) {
                authSequence = ASN1Util.as(DLSequence.class, stream);
            }
        }
        catch ( IOException e ) {
            throw new PACDecodingException("Malformed kerberos ticket", e);
        }

        this.authorizations = new ArrayList<>();
        Enumeration<?> authElements = authSequence.getObjects();
        while ( authElements.hasMoreElements() ) {
            DLSequence authElement = ASN1Util.as(DLSequence.class, authElements);
            ASN1Integer authType = ASN1Util.as(ASN1Integer.class, ASN1Util.as(DERTaggedObject.class, authElement, 0));
            DEROctetString authData = ASN1Util.as(DEROctetString.class, ASN1Util.as(DERTaggedObject.class, authElement, 1));

            this.authorizations.addAll(KerberosAuthData.parse(authType.getValue().intValue(), authData.getOctets(), key));
        }
    }


    public List<KerberosAuthData> getAuthorizations () {
        return this.authorizations;
    }

}
