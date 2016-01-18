/**
 * © 2016 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 17.01.2016 by mbechler
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
