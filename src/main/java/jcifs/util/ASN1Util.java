package jcifs.util;


import java.io.IOException;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DLSequence;

import jcifs.pac.PACDecodingException;


public final class ASN1Util {

    private ASN1Util () {}


    public static <T> T as ( Class<T> type, Object object ) throws PACDecodingException {
        if ( !type.isInstance(object) ) {
            throw new PACDecodingException("Incompatible object types " + type + " " + object.getClass());
        }

        return type.cast(object);
    }


    public static <T extends Object> T as ( Class<T> type, Enumeration<?> enumeration ) throws PACDecodingException {

        return as(type, enumeration.nextElement());
    }


    public static <T extends ASN1Primitive> T as ( Class<T> type, ASN1InputStream stream ) throws PACDecodingException, IOException {

        return as(type, stream.readObject());
    }


    public static <T extends ASN1Primitive> T as ( Class<T> type, ASN1TaggedObject tagged ) throws PACDecodingException {

        return as(type, tagged.getObject());
    }


    public static <T extends ASN1Primitive> T as ( Class<T> type, DLSequence sequence, int index ) throws PACDecodingException {
        return as(type, sequence.getObjectAt(index));
    }

}
