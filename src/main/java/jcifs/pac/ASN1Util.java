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
package jcifs.pac;


import java.io.IOException;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DLSequence;


/**
 * 
 *
 */
public final class ASN1Util {

    private ASN1Util () {}


    /**
     * 
     * @param type
     * @param object
     * @return object cast to type
     * @throws PACDecodingException
     */
    public static <T> T as ( Class<T> type, Object object ) throws PACDecodingException {
        if ( !type.isInstance(object) ) {
            throw new PACDecodingException("Incompatible object types " + type + " " + object.getClass());
        }

        return type.cast(object);
    }


    /**
     * 
     * @param type
     * @param enumeration
     * @return next element from enumeration cast to type
     * @throws PACDecodingException
     */
    public static <T extends Object> T as ( Class<T> type, Enumeration<?> enumeration ) throws PACDecodingException {
        return as(type, enumeration.nextElement());
    }


    /**
     * 
     * @param type
     * @param stream
     * @return next object from stream cast to type
     * @throws PACDecodingException
     * @throws IOException
     */
    public static <T extends ASN1Primitive> T as ( Class<T> type, ASN1InputStream stream ) throws PACDecodingException, IOException {
        return as(type, stream.readObject());
    }


    /**
     * 
     * @param type
     * @param tagged
     * @return tagged object contents cast to type
     * @throws PACDecodingException
     */
    public static <T extends ASN1Primitive> T as ( Class<T> type, ASN1TaggedObject tagged ) throws PACDecodingException {
        return as(type, tagged.getObject());
    }


    /**
     * 
     * @param type
     * @param sequence
     * @param index
     * @return sequence element cast to type
     * @throws PACDecodingException
     */
    public static <T extends ASN1Primitive> T as ( Class<T> type, DLSequence sequence, int index ) throws PACDecodingException {
        return as(type, sequence.getObjectAt(index));
    }

}
