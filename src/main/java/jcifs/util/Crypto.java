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


import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import jcifs.CIFSUnsupportedCryptoException;


/**
 * @author mbechler
 *
 */
public final class Crypto {

    private static final BouncyCastleProvider BCPROV = new BouncyCastleProvider();


    /**
     * 
     */
    private Crypto () {}


    /**
     * 
     * @return MD4 digest
     */
    public static MessageDigest getMD4 () {
        try {
            return MessageDigest.getInstance("MD4", BCPROV);
        }
        catch ( NoSuchAlgorithmException e ) {
            throw new CIFSUnsupportedCryptoException(e);
        }
    }


    /**
     * 
     * @return MD5 digest
     */
    public static MessageDigest getMD5 () {
        try {
            return MessageDigest.getInstance("MD5");
        }
        catch ( NoSuchAlgorithmException e ) {
            throw new CIFSUnsupportedCryptoException(e);
        }
    }


    /**
     * @return SHA512 digest
     */
    public static MessageDigest getSHA512 () {
        try {
            return MessageDigest.getInstance("SHA-512");
        }
        catch ( NoSuchAlgorithmException e ) {
            throw new CIFSUnsupportedCryptoException(e);
        }
    }


    /**
     * 
     * @param key
     * @return HMACT64 MAC
     */
    public static MessageDigest getHMACT64 ( byte[] key ) {
        return new HMACT64(key);
    }


    /**
     * 
     * @param key
     * @return RC4 cipher
     */
    public static Cipher getArcfour ( byte[] key ) {
        try {
            Cipher c = Cipher.getInstance("RC4");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "RC4"));
            return c;
        }
        catch (
            NoSuchAlgorithmException |
            NoSuchPaddingException |
            InvalidKeyException e ) {
            throw new CIFSUnsupportedCryptoException(e);
        }
    }


    /**
     * @param key
     *            7 or 8 byte DES key
     * @return DES cipher in encryption mode
     */
    public static Cipher getDES ( byte[] key ) {
        if ( key.length == 7 ) {
            return getDES(des7to8(key));
        }

        try {
            Cipher c = Cipher.getInstance("DES/ECB/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DES"));
            return c;
        }
        catch (
            NoSuchAlgorithmException |
            NoSuchPaddingException |
            InvalidKeyException e ) {
            throw new CIFSUnsupportedCryptoException(e);
        }
    }


    /**
     * @param key
     *            7-byte "raw" DES key
     * @return 8-byte DES key with parity
     */
    static byte[] des7to8 ( byte[] key ) {
        byte key8[] = new byte[8];
        key8[ 0 ] = (byte) ( key[ 0 ] & 0xFE );
        key8[ 1 ] = (byte) ( ( key[ 0 ] << 7 ) | ( ( key[ 1 ] & 0xFF ) >>> 1 ) );
        key8[ 2 ] = (byte) ( ( key[ 1 ] << 6 ) | ( ( key[ 2 ] & 0xFF ) >>> 2 ) );
        key8[ 3 ] = (byte) ( ( key[ 2 ] << 5 ) | ( ( key[ 3 ] & 0xFF ) >>> 3 ) );
        key8[ 4 ] = (byte) ( ( key[ 3 ] << 4 ) | ( ( key[ 4 ] & 0xFF ) >>> 4 ) );
        key8[ 5 ] = (byte) ( ( key[ 4 ] << 3 ) | ( ( key[ 5 ] & 0xFF ) >>> 5 ) );
        key8[ 6 ] = (byte) ( ( key[ 5 ] << 2 ) | ( ( key[ 6 ] & 0xFF ) >>> 6 ) );
        key8[ 7 ] = (byte) ( key[ 6 ] << 1 );
        for ( int i = 0; i < key8.length; i++ ) {
            key8[ i ] ^= Integer.bitCount(key8[ i ] ^ 1) & 1;
        }
        return key8;
    }

}
