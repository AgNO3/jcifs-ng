/*
 * © 2017 AgNO3 Gmbh & Co. KG
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
package jcifs.internal.smb2;


import java.nio.charset.StandardCharsets;

import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.KDFCounterBytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KDFCounterParameters;


/**
 * SMB3 SP800-108 Counter Mode Key Derivation
 * 
 * @author mbechler
 *
 */
final class Smb3KeyDerivation {

    private static final byte[] SIGNCONTEXT_300 = toCBytes("SmbSign");
    private static final byte[] SIGNLABEL_300 = toCBytes("SMB2AESCMAC");
    private static final byte[] SIGNLABEL_311 = toCBytes("SMBSigningKey");

    private static final byte[] APPCONTEXT_300 = toCBytes("SmbRpc");
    private static final byte[] APPLABEL_300 = toCBytes("SMB2APP");
    private static final byte[] APPLABEL_311 = toCBytes("SMBAppKey");

    private static final byte[] ENCCONTEXT_300 = toCBytes("ServerIn "); // there really is a space there
    private static final byte[] ENCLABEL_300 = toCBytes("SMB2AESCCM");
    private static final byte[] ENCLABEL_311 = toCBytes("SMB2C2SCipherKey");

    private static final byte[] DECCONTEXT_300 = toCBytes("ServerOut");
    private static final byte[] DECLABEL_300 = toCBytes("SMB2AESCCM");
    private static final byte[] DECLABEL_311 = toCBytes("SMB2S2CCipherKey");


    /**
     * 
     */
    private Smb3KeyDerivation () {}


    /**
     * 
     * @param dialect
     * @param sessionKey
     * @param preauthIntegrity
     * @return derived signing key
     */
    public static byte[] deriveSigningKey ( int dialect, byte[] sessionKey, byte[] preauthIntegrity ) {
        return derive(
            sessionKey,
            dialect == Smb2Constants.SMB2_DIALECT_0311 ? SIGNLABEL_311 : SIGNLABEL_300,
            dialect == Smb2Constants.SMB2_DIALECT_0311 ? preauthIntegrity : SIGNCONTEXT_300);
    }


    /**
     * 
     * @param dialect
     * @param sessionKey
     * @param preauthIntegrity
     * @return derived application key
     */
    public static byte[] dervieApplicationKey ( int dialect, byte[] sessionKey, byte[] preauthIntegrity ) {
        return derive(
            sessionKey,
            dialect == Smb2Constants.SMB2_DIALECT_0311 ? APPLABEL_311 : APPLABEL_300,
            dialect == Smb2Constants.SMB2_DIALECT_0311 ? preauthIntegrity : APPCONTEXT_300);
    }


    /**
     * 
     * @param dialect
     * @param sessionKey
     * @param preauthIntegrity
     * @return derived encryption key
     */
    public static byte[] deriveEncryptionKey ( int dialect, byte[] sessionKey, byte[] preauthIntegrity ) {
        return derive(
            sessionKey,
            dialect == Smb2Constants.SMB2_DIALECT_0311 ? ENCLABEL_311 : ENCLABEL_300,
            dialect == Smb2Constants.SMB2_DIALECT_0311 ? preauthIntegrity : ENCCONTEXT_300);
    }


    /**
     * 
     * @param dialect
     * @param sessionKey
     * @param preauthIntegrity
     * @return derived decryption key
     */
    public static byte[] deriveDecryptionKey ( int dialect, byte[] sessionKey, byte[] preauthIntegrity ) {
        return derive(
            sessionKey,
            dialect == Smb2Constants.SMB2_DIALECT_0311 ? DECLABEL_311 : DECLABEL_300,
            dialect == Smb2Constants.SMB2_DIALECT_0311 ? preauthIntegrity : DECCONTEXT_300);

    }


    /**
     * @param sessionKey
     * @param label
     * @param context
     */
    private static byte[] derive ( byte[] sessionKey, byte[] label, byte[] context ) {
        KDFCounterBytesGenerator gen = new KDFCounterBytesGenerator(new HMac(new SHA256Digest()));

        int r = 32;
        byte[] suffix = new byte[label.length + context.length + 5];
        // per bouncycastle
        // <li>1: K(i) := PRF( KI, [i]_2 || Label || 0x00 || Context || [L]_2 ) with the counter at the very beginning
        // of the fixedInputData (The default implementation has this format)</li>
        // with the parameters
        // <li>1. KDFCounterParameters(ki, null, "Label || 0x00 || Context || [L]_2]", 8);

        // all fixed inputs go into the suffix:
        // + label
        System.arraycopy(label, 0, suffix, 0, label.length);
        // + 1 byte 0x00
        // + context
        System.arraycopy(context, 0, suffix, label.length + 1, context.length);
        // + 4 byte (== r bits) big endian encoding of L
        suffix[ suffix.length - 1 ] = (byte) 128;

        DerivationParameters param = new KDFCounterParameters(sessionKey, null /* prefix */, suffix /* suffix */, r /* r */);
        gen.init(param);

        byte[] derived = new byte[16];
        gen.generateBytes(derived, 0, 16);
        return derived;
    }


    /**
     * @param string
     * @return null terminated ASCII bytes
     */
    private static byte[] toCBytes ( String string ) {
        byte[] data = new byte[string.length() + 1];
        System.arraycopy(string.getBytes(StandardCharsets.US_ASCII), 0, data, 0, string.length());
        return data;
    }

}
