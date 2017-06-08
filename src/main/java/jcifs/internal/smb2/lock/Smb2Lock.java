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
package jcifs.internal.smb2.lock;


import jcifs.Encodable;
import jcifs.internal.util.SMBUtil;


/**
 * @author mbechler
 *
 */
public class Smb2Lock implements Encodable {

    /**
     * 
     */
    public static final int SMB2_LOCKFLAG_SHARED_LOCK = 0x1;

    /**
     * 
     */
    public static final int SMB2_LOCKFLAG_EXCLUSIVE_LOCK = 0x2;

    /**
     * 
     */
    public static final int SMB2_LOCKFLAG_UNLOCK = 0x4;

    /**
     * 
     */
    public static final int SMB2_LOCKFLAG_FAIL_IMMEDIATELY = 0x10;

    private long offset;
    private long length;
    private int flags;


    /**
     * @param offset
     * @param length
     * @param flags
     */
    public Smb2Lock ( long offset, long length, int flags ) {
        this.offset = offset;
        this.length = length;
        this.flags = flags;

    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Encodable#size()
     */
    @Override
    public int size () {
        return 24;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Encodable#encode(byte[], int)
     */
    @Override
    public int encode ( byte[] dst, int dstIndex ) {
        int start = dstIndex;
        SMBUtil.writeInt8(this.offset, dst, dstIndex);
        dstIndex += 8;
        SMBUtil.writeInt8(this.length, dst, dstIndex);
        dstIndex += 8;

        SMBUtil.writeInt4(this.flags, dst, dstIndex);
        dstIndex += 4;
        dstIndex += 4; // Reserved
        return dstIndex - start;
    }

}
