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


    public static MessageDigest getMD4 () {
        try {
            return MessageDigest.getInstance("MD4", BCPROV);
        }
        catch ( NoSuchAlgorithmException e ) {
            throw new CIFSUnsupportedCryptoException(e);
        }
    }


    public static MessageDigest getMD5 () {
        try {
            return MessageDigest.getInstance("MD5");
        }
        catch ( NoSuchAlgorithmException e ) {
            throw new CIFSUnsupportedCryptoException(e);
        }
    }


    public static MessageDigest getHMACT64 ( byte[] key ) {
        return new HMACT64(key);
    }


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
     * @param k1
     * @return
     */
    public static Cipher getDES ( byte[] key ) {
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

}
