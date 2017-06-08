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
package jcifs.internal.smb2.ioctl;


import jcifs.Encodable;
import jcifs.internal.util.SMBUtil;


/**
 * @author mbechler
 *
 */
public class SrvCopychunkCopy implements Encodable {

    private final byte[] sourceKey;
    private final SrvCopychunk[] chunks;


    /**
     * @param sourceKey
     * @param chunks
     * 
     */
    public SrvCopychunkCopy ( byte[] sourceKey, SrvCopychunk... chunks ) {
        this.sourceKey = sourceKey;
        this.chunks = chunks;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Encodable#encode(byte[], int)
     */
    @Override
    public int encode ( byte[] dst, int dstIndex ) {
        int start = dstIndex;

        System.arraycopy(this.sourceKey, 0, dst, dstIndex, 24);
        dstIndex += 24;

        SMBUtil.writeInt4(this.chunks.length, dst, dstIndex);
        dstIndex += 4;

        dstIndex += 4; // Reserved

        for ( SrvCopychunk chk : this.chunks ) {
            dstIndex += chk.encode(dst, dstIndex);
        }
        return dstIndex - start;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Encodable#size()
     */
    @Override
    public int size () {
        return 32 + this.chunks.length * 24;
    }

}
