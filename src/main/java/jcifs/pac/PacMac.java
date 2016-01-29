package jcifs.pac;


import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.spec.SecretKeySpec;

import jcifs.util.Encdec;


public class PacMac {

    private static final String HMAC_ALGORITHM = "hmac";
    private static final String SIGNATURE_KEY = "signaturekey\0";

    private MessageDigest messageDigest;
    private MessageDigest macMessageDigest;

    private byte[] constant;
    private byte[] xorInputPad;
    private byte[] xorOutputPad;


    public void init ( Key key ) throws NoSuchAlgorithmException {
        this.messageDigest = MessageDigest.getInstance("MD5");
        this.macMessageDigest = MessageDigest.getInstance("MD5");

        macInit(new SecretKeySpec(key.getEncoded(), HMAC_ALGORITHM));
        try {
            this.constant = SIGNATURE_KEY.getBytes("UTF8");
        }
        catch ( UnsupportedEncodingException e ) {
            this.constant = SIGNATURE_KEY.getBytes();
        }
        this.macMessageDigest.update(this.constant);
        byte digest[] = macDigest();

        macInit(new SecretKeySpec(digest, HMAC_ALGORITHM));
        byte[] encType = new byte[4];
        Encdec.enc_uint32le(PacConstants.MD5_KRB_SALT, encType, 0);
        this.messageDigest.update(encType);
    }


    public void update ( byte toUpdate[] ) {
        this.messageDigest.update(toUpdate);
    }


    public byte[] doFinal () {
        byte[] digest = this.messageDigest.digest();
        this.macMessageDigest.update(digest);

        return macDigest();
    }


    private void macInit ( Key key ) {
        this.xorInputPad = new byte[PacConstants.MD5_BLOCK_LENGTH];
        this.xorOutputPad = new byte[PacConstants.MD5_BLOCK_LENGTH];

        byte[] keyData = key.getEncoded();
        if ( keyData.length > PacConstants.MD5_BLOCK_LENGTH ) {
            this.macMessageDigest.reset();
            keyData = this.macMessageDigest.digest(keyData);
        }

        System.arraycopy(keyData, 0, this.xorInputPad, 0, keyData.length);
        System.arraycopy(keyData, 0, this.xorOutputPad, 0, keyData.length);

        for ( int i = 0; i < PacConstants.MD5_BLOCK_LENGTH; i++ ) {
            this.xorInputPad[ i ] ^= 0x36;
            this.xorOutputPad[ i ] ^= 0x5c;
        }

        this.macMessageDigest.reset();
        this.macMessageDigest.update(this.xorInputPad);
    }


    private byte[] macDigest () {
        byte[] digest = this.macMessageDigest.digest();
        this.macMessageDigest.update(this.xorOutputPad);

        digest = this.macMessageDigest.digest(digest);
        this.macMessageDigest.update(this.xorInputPad);

        return digest;
    }

}
