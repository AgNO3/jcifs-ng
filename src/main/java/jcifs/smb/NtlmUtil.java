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
package jcifs.smb;


import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.ShortBufferException;

import jcifs.CIFSContext;
import jcifs.util.Crypto;
import jcifs.util.Encdec;
import jcifs.util.Strings;


/**
 * Internal use only
 * 
 * @author mbechler
 * @internal
 */
public final class NtlmUtil {

    /**
     * 
     */
    private NtlmUtil () {}


    /**
     * 
     * @param responseKeyNT
     * @param serverChallenge
     * @param clientChallenge
     * @param nanos1601
     * @param avPairs
     * @return the calculated response
     */
    public static byte[] getNTLMv2Response ( byte[] responseKeyNT, byte[] serverChallenge, byte[] clientChallenge, long nanos1601, byte[] avPairs ) {
        int avPairsLength = avPairs != null ? avPairs.length : 0;
        byte[] temp = new byte[28 + avPairsLength + 4];

        Encdec.enc_uint32le(0x00000101, temp, 0); // Header
        Encdec.enc_uint32le(0x00000000, temp, 4); // Reserved
        Encdec.enc_uint64le(nanos1601, temp, 8);
        System.arraycopy(clientChallenge, 0, temp, 16, 8);
        Encdec.enc_uint32le(0x00000000, temp, 24); // Unknown
        if ( avPairs != null )
            System.arraycopy(avPairs, 0, temp, 28, avPairsLength);
        Encdec.enc_uint32le(0x00000000, temp, 28 + avPairsLength); // mystery bytes!

        return NtlmUtil.computeResponse(responseKeyNT, serverChallenge, temp, 0, temp.length);
    }


    /**
     * 
     * @param responseKeyLM
     * @param serverChallenge
     * @param clientChallenge
     * @return the calculated response
     */
    public static byte[] getLMv2Response ( byte[] responseKeyLM, byte[] serverChallenge, byte[] clientChallenge ) {
        return NtlmUtil.computeResponse(responseKeyLM, serverChallenge, clientChallenge, 0, clientChallenge.length);
    }


    static byte[] computeResponse ( byte[] responseKey, byte[] serverChallenge, byte[] clientData, int offset, int length ) {
        MessageDigest hmac = Crypto.getHMACT64(responseKey);
        hmac.update(serverChallenge);
        hmac.update(clientData, offset, length);
        byte[] mac = hmac.digest();
        byte[] ret = new byte[mac.length + clientData.length];
        System.arraycopy(mac, 0, ret, 0, mac.length);
        System.arraycopy(clientData, 0, ret, mac.length, clientData.length);
        return ret;
    }


    /**
     * 
     * @param domain
     * @param username
     * @param password
     * 
     * @return the caclulated mac
     */
    public static byte[] nTOWFv2 ( String domain, String username, String password ) {
        MessageDigest md4 = Crypto.getMD4();
        md4.update(Strings.getUNIBytes(password));
        MessageDigest hmac = Crypto.getHMACT64(md4.digest());
        hmac.update(Strings.getUNIBytes(username.toUpperCase()));
        hmac.update(Strings.getUNIBytes(domain));
        return hmac.digest();
    }


    /**
     * 
     * @param password
     * @return the calculated hash
     */
    public static byte[] nTOWFv1 ( String password ) {
        if ( password == null )
            throw new NullPointerException("Password parameter is required");
        MessageDigest md4 = Crypto.getMD4();
        md4.update(Strings.getUNIBytes(password));
        return md4.digest();
    }


    /**
     * 
     * @param nTOWFv1
     * @param serverChallenge
     * @param clientChallenge
     * @return the calculated response
     * @throws GeneralSecurityException
     */
    public static byte[] getNTLM2Response ( byte[] nTOWFv1, byte[] serverChallenge, byte[] clientChallenge ) throws GeneralSecurityException {
        byte[] sessionHash = new byte[8];

        MessageDigest md5 = Crypto.getMD5();;
        md5.update(serverChallenge);
        md5.update(clientChallenge, 0, 8);
        System.arraycopy(md5.digest(), 0, sessionHash, 0, 8);

        byte[] key = new byte[21];
        System.arraycopy(nTOWFv1, 0, key, 0, 16);
        byte[] ntResponse = new byte[24];
        NtlmUtil.E(key, sessionHash, ntResponse);
        return ntResponse;
    }


    /**
     * Creates the LMv2 response for the supplied information.
     *
     * @param domain
     *            The domain in which the username exists.
     * @param user
     *            The username.
     * @param password
     *            The user's password.
     * @param challenge
     *            The server challenge.
     * @param clientChallenge
     *            The client challenge (nonce).
     * @return the calculated response
     * @throws GeneralSecurityException
     */
    public static byte[] getLMv2Response ( String domain, String user, String password, byte[] challenge, byte[] clientChallenge )
            throws GeneralSecurityException {
        byte[] response = new byte[24];
        // The next 2-1/2 lines of this should be placed with nTOWFv1 in place of password
        MessageDigest md4 = Crypto.getMD4();
        md4.update(Strings.getUNIBytes(password));
        MessageDigest hmac = Crypto.getHMACT64(md4.digest());
        hmac.update(Strings.getUNIBytes(user.toUpperCase()));
        hmac.update(Strings.getUNIBytes(domain.toUpperCase()));
        hmac = Crypto.getHMACT64(hmac.digest());
        hmac.update(challenge);
        hmac.update(clientChallenge);
        hmac.digest(response, 0, 16);
        System.arraycopy(clientChallenge, 0, response, 16, 8);
        return response;
    }


    /**
     * Generate the Unicode MD4 hash for the password associated with these credentials.
     * 
     * @param password
     * @param challenge
     * @return the calculated response
     * @throws GeneralSecurityException
     */
    static public byte[] getNTLMResponse ( String password, byte[] challenge ) throws GeneralSecurityException {
        byte[] p21 = new byte[21];
        byte[] p24 = new byte[24];

        byte[] uni = Strings.getUNIBytes(password);
        MessageDigest md4 = Crypto.getMD4();
        md4.update(uni);
        md4.digest(p21, 0, 16);
        NtlmUtil.E(p21, challenge, p24);
        return p24;
    }


    /**
     * Generate the ANSI DES hash for the password associated with these credentials.
     * 
     * @param tc
     * @param password
     * @param challenge
     * @return the calculated response
     * @throws GeneralSecurityException
     */
    static public byte[] getPreNTLMResponse ( CIFSContext tc, String password, byte[] challenge ) throws GeneralSecurityException {
        byte[] p14 = new byte[14];
        byte[] p21 = new byte[21];
        byte[] p24 = new byte[24];
        byte[] passwordBytes = Strings.getOEMBytes(password, tc.getConfig());
        int passwordLength = passwordBytes.length;

        // Only encrypt the first 14 bytes of the password for Pre 0.12 NT LM
        if ( passwordLength > 14 ) {
            passwordLength = 14;
        }
        System.arraycopy(passwordBytes, 0, p14, 0, passwordLength);
        NtlmUtil.E(p14, NtlmUtil.S8, p21);
        NtlmUtil.E(p21, challenge, p24);
        return p24;
    }

    // KGS!@#$%
    static final byte[] S8 = {
        (byte) 0x4b, (byte) 0x47, (byte) 0x53, (byte) 0x21, (byte) 0x40, (byte) 0x23, (byte) 0x24, (byte) 0x25
    };


    /*
     * Accepts key multiple of 7
     * Returns enc multiple of 8
     * Multiple is the same like: 21 byte key gives 24 byte result
     */
    static void E ( byte[] key, byte[] data, byte[] e ) throws ShortBufferException {
        byte[] key7 = new byte[7];
        byte[] e8 = new byte[8];

        for ( int i = 0; i < key.length / 7; i++ ) {
            System.arraycopy(key, i * 7, key7, 0, 7);
            Cipher des = Crypto.getDES(key7);
            des.update(data, 0, data.length, e8);
            System.arraycopy(e8, 0, e, i * 8, 8);
        }
    }

}
