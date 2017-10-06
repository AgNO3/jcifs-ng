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
public class ValidateNegotiateInfoRequest implements Encodable {

    private int capabilities;
    private byte[] clientGuid;
    private int securityMode;
    private int dialects[];


    /**
     * @param capabilities
     * @param clientGuid
     * @param securityMode
     * @param dialects
     * 
     */
    public ValidateNegotiateInfoRequest ( int capabilities, byte[] clientGuid, int securityMode, int[] dialects ) {
        this.capabilities = capabilities;
        this.clientGuid = clientGuid;
        this.securityMode = securityMode;
        this.dialects = dialects;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Encodable#encode(byte[], int)
     */
    @Override
    public int encode ( byte[] dst, int dstIndex ) {
        int start = dstIndex;

        SMBUtil.writeInt4(this.capabilities, dst, dstIndex);
        dstIndex += 4;

        System.arraycopy(this.clientGuid, 0, dst, dstIndex, 16);
        dstIndex += 16;

        SMBUtil.writeInt2(this.securityMode, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt2(this.dialects.length, dst, dstIndex);
        dstIndex += 2;

        for ( int dialect : this.dialects ) {
            SMBUtil.writeInt2(dialect, dst, dstIndex);
            dstIndex += 2;
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
        return 24 + 2 * this.dialects.length;
    }

}
