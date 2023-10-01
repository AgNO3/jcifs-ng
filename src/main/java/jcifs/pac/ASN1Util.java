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


import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;

import org.bouncycastle.asn1.*;


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
        return as(type, tagged.getBaseObject());
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
        return as(type, sequence, index);
    }

    /**
     * 
     * @param type
     * @param sequence
     * @param index
     * @return sequence element cast to type
     * @throws PACDecodingException
     */
    public static <T extends ASN1Primitive> T as ( Class<T> type, ASN1Sequence sequence, int index ) throws PACDecodingException {
        return as(type, sequence.getObjectAt(index));
    }


    /**
     * Read a  tagged object without parsing it's contents
     *
     * BC no longer seems to allow that out of the box
     *
     * @param expectTag
     * @param in
     * @return coded bytes of the tagged object
     * @throws IOException
     */
    public static byte[] readUnparsedTagged(int expectTag, int limit, ASN1InputStream in) throws IOException {
        int ftag = in.read();
        int tag = readTagNumber(in, ftag);
        if ( tag != expectTag ) {
            throw new IOException("Unexpected tag " + tag);
        }
        int length = readLength(in, limit, false);
        byte[] content = new byte[length];
        in.read(content);
        return content;
    }

    // shamelessly stolen from BC ASN1InputStream
    static int readTagNumber(InputStream s, int tag)
            throws IOException
    {
        int tagNo = tag & 0x1f;

        //
        // with tagged object tag number is bottom 5 bits, or stored at the start of the content
        //
        if (tagNo == 0x1f)
        {
            int b = s.read();
            if (b < 31)
            {
                if (b < 0)
                {
                    throw new EOFException("EOF found inside tag value.");
                }
                throw new IOException("corrupted stream - high tag number < 31 found");
            }

            tagNo = b & 0x7f;

            // X.690-0207 8.1.2.4.2
            // "c) bits 7 to 1 of the first subsequent octet shall not all be zero."
            if (0 == tagNo)
            {
                throw new IOException("corrupted stream - invalid high tag number found");
            }

            while ((b & 0x80) != 0)
            {
                if ((tagNo >>> 24) != 0)
                {
                    throw new IOException("Tag number more than 31 bits");
                }

                tagNo <<= 7;

                b = s.read();
                if (b < 0)
                {
                    throw new EOFException("EOF found inside tag value.");
                }

                tagNo |= (b & 0x7f);
            }
        }

        return tagNo;
    }

    static int readLength(InputStream s, int limit, boolean isParsing)
            throws IOException
    {
        int length = s.read();
        if (0 == (length >>> 7))
        {
            // definite-length short form
            return length;
        }
        if (0x80 == length)
        {
            // indefinite-length
            return -1;
        }
        if (length < 0)
        {
            throw new EOFException("EOF found when length expected");
        }
        if (0xFF == length)
        {
            throw new IOException("invalid long form definite-length 0xFF");
        }

        int octetsCount = length & 0x7F, octetsPos = 0;

        length = 0;
        do
        {
            int octet = s.read();
            if (octet < 0)
            {
                throw new EOFException("EOF found reading length");
            }

            if ((length >>> 23) != 0)
            {
                throw new IOException("long form definite-length more than 31 bits");
            }

            length = (length << 8) + octet;
        }
        while (++octetsPos < octetsCount);

        if (length >= limit && !isParsing)   // after all we must have read at least 1 byte
        {
            throw new IOException("corrupted stream - out of bounds length found: " + length + " >= " + limit);
        }

        return length;
    }

}
