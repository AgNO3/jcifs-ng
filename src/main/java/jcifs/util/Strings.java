/**
 * © 2016 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 17.01.2016 by mbechler
 */
package jcifs.util;


import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;

import jcifs.Configuration;
import jcifs.RuntimeCIFSException;


/**
 * @author mbechler
 *
 */
public final class Strings {

    private static final Charset UNI_ENCODING = Charset.forName("UTF-16LE");
    private static final Charset ASCII_ENCODING = Charset.forName("US-ASCII");


    /**
     * 
     */
    private Strings () {}


    public static byte[] getBytes ( String str, Charset encoding ) {
        if ( str == null ) {
            return new byte[0];
        }
        return str.getBytes(encoding);
    }


    public static byte[] getUNIBytes ( String str ) {
        return getBytes(str, UNI_ENCODING);
    }


    public static byte[] getASCIIBytes ( String str ) {
        return getBytes(str, ASCII_ENCODING);
    }


    /**
     * @param password
     * @param config
     * @return the string as bytes
     */
    public static byte[] getOEMBytes ( String str, Configuration config ) {
        if ( str == null ) {
            return new byte[0];
        }
        try {
            return str.getBytes(config.getOemEncoding());
        }
        catch ( UnsupportedEncodingException e ) {
            throw new RuntimeCIFSException("Unsupported OEM encoding " + config.getOemEncoding(), e);
        }
    }


    /**
     * @param src
     * @param srcIndex
     * @param len
     * @return
     */
    public static String fromUNIBytes ( byte[] src, int srcIndex, int len ) {
        return new String(src, srcIndex, len, UNI_ENCODING);
    }


    /**
     * @param buffer
     * @param bufferIndex
     * @param len
     * @return
     */
    public static int findUNITermination ( byte[] buffer, int bufferIndex, int maxLen ) {
        int len = 0;
        while ( buffer[ bufferIndex + len ] != (byte) 0x00 || buffer[ bufferIndex + len + 1 ] != (byte) 0x00 ) {
            len += 2;
            if ( len > maxLen ) {
                throw new RuntimeCIFSException("zero termination not found");
            }
        }
        return len;
    }


    /**
     * @param src
     * @param srcIndex
     * @param len
     * @param config
     * @return
     */
    public static String fromOEMBytes ( byte[] src, int srcIndex, int len, Configuration config ) {
        try {
            return new String(src, srcIndex, len, config.getOemEncoding());
        }
        catch ( UnsupportedEncodingException e ) {
            throw new RuntimeCIFSException("Unsupported OEM encoding " + config.getOemEncoding(), e);
        }
    }


    /**
     * @param buffer
     * @param bufferIndex
     * @param len
     * @return
     */
    public static int findTermination ( byte[] buffer, int bufferIndex, int maxLen ) {
        int len = 0;
        while ( buffer[ bufferIndex + len ] != (byte) 0x00 ) {
            len++;
            if ( len > maxLen ) {
                throw new RuntimeCIFSException("zero termination not found");
            }
        }
        return len;
    }
}
