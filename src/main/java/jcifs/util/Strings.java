/*
 * © 2016 AgNO3 Gmbh & Co. KG
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
package jcifs.util;


import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.Configuration;
import jcifs.RuntimeCIFSException;


/**
 * @author mbechler
 *
 */
public final class Strings {

    private static final Logger log = LoggerFactory.getLogger(Strings.class);

    private static final Charset UNI_ENCODING = Charset.forName("UTF-16LE");
    private static final Charset ASCII_ENCODING = Charset.forName("US-ASCII");


    /**
     * 
     */
    private Strings () {}


    /**
     * 
     * @param str
     * @param encoding
     * @return encoded
     */
    public static byte[] getBytes ( String str, Charset encoding ) {
        if ( str == null ) {
            return new byte[0];
        }
        return str.getBytes(encoding);
    }


    /**
     * 
     * @param str
     * @return the string as bytes (UTF16-LE)
     */
    public static byte[] getUNIBytes ( String str ) {
        return getBytes(str, UNI_ENCODING);
    }


    /**
     * 
     * @param str
     * @return the string as bytes (ASCII)
     */
    public static byte[] getASCIIBytes ( String str ) {
        return getBytes(str, ASCII_ENCODING);
    }


    /**
     * @param str
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
     * @return decoded string
     */
    public static String fromUNIBytes ( byte[] src, int srcIndex, int len ) {
        return new String(src, srcIndex, len, UNI_ENCODING);
    }


    /**
     * @param buffer
     * @param bufferIndex
     * @param maxLen
     * @return position of terminating null bytes
     */
    public static int findUNITermination ( byte[] buffer, int bufferIndex, int maxLen ) {
        int len = 0;
        while ( buffer[ bufferIndex + len ] != (byte) 0x00 || buffer[ bufferIndex + len + 1 ] != (byte) 0x00 ) {
            len += 2;
            if ( len > maxLen ) {
                if ( log.isDebugEnabled() ) {
                    log.warn("Failed to find string termination with max length " + maxLen);
                    log.debug(Hexdump.toHexString(buffer, bufferIndex, len));
                }
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
     * @return decoded string
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
     * @param maxLen
     * @return position of terminating null byte
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
