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
package jcifs.internal.smb2.nego;


import jcifs.Configuration;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.util.SMBUtil;


/**
 * @author mbechler
 *
 */
public class PreauthIntegrityNegotiateContext implements NegotiateContextRequest, NegotiateContextResponse {

    /**
     * Context type
     */
    public static final int NEGO_CTX_PREAUTH_TYPE = 0x1;

    /**
     * SHA-512
     */
    public static final int HASH_ALGO_SHA512 = 0x1;

    private int[] hashAlgos;
    private byte[] salt;


    /**
     * 
     * @param config
     * @param hashAlgos
     * @param salt
     */
    public PreauthIntegrityNegotiateContext ( Configuration config, int[] hashAlgos, byte[] salt ) {
        this.hashAlgos = hashAlgos;
        this.salt = salt;
    }


    /**
     * 
     */
    public PreauthIntegrityNegotiateContext () {}


    /**
     * @return the salt
     */
    public byte[] getSalt () {
        return this.salt;
    }


    /**
     * @return the hashAlgos
     */
    public int[] getHashAlgos () {
        return this.hashAlgos;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.nego.NegotiateContextRequest#getContextType()
     */
    @Override
    public int getContextType () {
        return NEGO_CTX_PREAUTH_TYPE;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Encodable#encode(byte[], int)
     */
    @Override
    public int encode ( byte[] dst, int dstIndex ) {
        int start = dstIndex;

        SMBUtil.writeInt2(this.hashAlgos != null ? this.hashAlgos.length : 0, dst, dstIndex);
        SMBUtil.writeInt2(this.salt != null ? this.salt.length : 0, dst, dstIndex + 2);
        dstIndex += 4;

        if ( this.hashAlgos != null ) {
            for ( int hashAlgo : this.hashAlgos ) {
                SMBUtil.writeInt2(hashAlgo, dst, dstIndex);
                dstIndex += 2;
            }
        }

        if ( this.salt != null ) {
            System.arraycopy(this.salt, 0, dst, dstIndex, this.salt.length);
            dstIndex += this.salt.length;
        }

        return dstIndex - start;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Decodable#decode(byte[], int, int)
     */
    @Override
    public int decode ( byte[] buffer, int bufferIndex, int len ) throws SMBProtocolDecodingException {
        int start = bufferIndex;
        int nalgos = SMBUtil.readInt2(buffer, bufferIndex);
        int nsalt = SMBUtil.readInt2(buffer, bufferIndex + 2);
        bufferIndex += 4;

        this.hashAlgos = new int[nalgos];
        for ( int i = 0; i < nalgos; i++ ) {
            this.hashAlgos[ i ] = SMBUtil.readInt2(buffer, bufferIndex);
            bufferIndex += 2;
        }

        this.salt = new byte[nsalt];
        System.arraycopy(buffer, bufferIndex, this.salt, 0, nsalt);
        bufferIndex += nsalt;

        return bufferIndex - start;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Encodable#size()
     */
    @Override
    public int size () {
        return 4 + ( this.hashAlgos != null ? 2 * this.hashAlgos.length : 0 ) + ( this.salt != null ? this.salt.length : 0 );
    }

}
