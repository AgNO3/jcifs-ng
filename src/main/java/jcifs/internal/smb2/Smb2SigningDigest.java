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


import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Provider;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.internal.CommonServerMessageBlock;
import jcifs.internal.SMBSigningDigest;
import jcifs.internal.util.SMBUtil;


/**
 * @author mbechler
 *
 */
public class Smb2SigningDigest implements SMBSigningDigest {

    private static final Logger log = LoggerFactory.getLogger(Smb2SigningDigest.class);

    /**
     * 
     */
    private static final int SIGNATURE_OFFSET = 48;
    private static final int SIGNATURE_LENGTH = 16;
    private final Mac digest;

    private static final Provider BC = new BouncyCastleProvider();


    /**
     * @param sessionKey
     * @param dialect
     * @param preauthIntegrityHash
     * @throws GeneralSecurityException
     * 
     */
    public Smb2SigningDigest ( byte[] sessionKey, int dialect, byte[] preauthIntegrityHash ) throws GeneralSecurityException {
        Mac m;
        byte[] signingKey;
        switch ( dialect ) {
        case Smb2Constants.SMB2_DIALECT_0202:
        case Smb2Constants.SMB2_DIALECT_0210:
            m = Mac.getInstance("HmacSHA256");
            signingKey = sessionKey;
            break;
        case Smb2Constants.SMB2_DIALECT_0300:
        case Smb2Constants.SMB2_DIALECT_0302:
            signingKey = Smb3KeyDerivation.deriveSigningKey(dialect, sessionKey, new byte[0] /* unimplemented */);
            m = Mac.getInstance("AESCMAC", BC);
            break;
        case Smb2Constants.SMB2_DIALECT_0311:
            if ( preauthIntegrityHash == null ) {
                throw new IllegalArgumentException("Missing preauthIntegrityHash for SMB 3.1");
            }
            signingKey = Smb3KeyDerivation.deriveSigningKey(dialect, sessionKey, preauthIntegrityHash);
            m = Mac.getInstance("AESCMAC", BC);
            break;
        default:
            throw new IllegalArgumentException("Unknown dialect");
        }

        m.init(new SecretKeySpec(signingKey, "HMAC"));
        this.digest = m;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SMBSigningDigest#sign(byte[], int, int, jcifs.internal.CommonServerMessageBlock,
     *      jcifs.internal.CommonServerMessageBlock)
     */
    @Override
    public synchronized void sign ( byte[] data, int offset, int length, CommonServerMessageBlock request, CommonServerMessageBlock response ) {
        this.digest.reset();

        // zero out signature field
        int index = offset + SIGNATURE_OFFSET;
        for ( int i = 0; i < SIGNATURE_LENGTH; i++ )
            data[ index + i ] = 0;

        // set signed flag
        int oldFlags = SMBUtil.readInt4(data, offset + 16);
        int flags = oldFlags | ServerMessageBlock2.SMB2_FLAGS_SIGNED;
        SMBUtil.writeInt4(flags, data, offset + 16);

        this.digest.update(data, offset, length);

        byte[] sig = this.digest.doFinal();
        System.arraycopy(sig, 0, data, offset + SIGNATURE_OFFSET, SIGNATURE_LENGTH);
    }


    /**
     * 
     * {@inheritDoc}
     *
     * @see jcifs.internal.SMBSigningDigest#verify(byte[], int, int, int, jcifs.internal.CommonServerMessageBlock)
     */
    @Override
    public synchronized boolean verify ( byte[] data, int offset, int length, int extraPad, CommonServerMessageBlock msg ) {
        this.digest.reset();

        int flags = SMBUtil.readInt4(data, offset + 16);
        if ( ( flags & ServerMessageBlock2.SMB2_FLAGS_SIGNED ) == 0 ) {
            log.error("The server did not sign a message we expected to be signed");
            return true;
        }

        byte[] sig = new byte[SIGNATURE_LENGTH];
        System.arraycopy(data, offset + SIGNATURE_OFFSET, sig, 0, SIGNATURE_LENGTH);

        int index = offset + SIGNATURE_OFFSET;
        for ( int i = 0; i < SIGNATURE_LENGTH; i++ )
            data[ index + i ] = 0;

        this.digest.update(data, offset, length);

        byte[] cmp = new byte[SIGNATURE_LENGTH];
        System.arraycopy(this.digest.doFinal(), 0, cmp, 0, SIGNATURE_LENGTH);
        if ( !MessageDigest.isEqual(sig, cmp) ) {
            return true;
        }
        return false;
    }

}
