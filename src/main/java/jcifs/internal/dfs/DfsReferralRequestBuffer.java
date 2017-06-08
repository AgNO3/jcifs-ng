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
package jcifs.internal.dfs;


import java.nio.charset.StandardCharsets;

import jcifs.Encodable;
import jcifs.internal.util.SMBUtil;


/**
 * @author mbechler
 *
 */
public class DfsReferralRequestBuffer implements Encodable {

    private final int maxReferralLevel;
    private final String path;


    /**
     * @param filename
     * @param maxReferralLevel
     */
    public DfsReferralRequestBuffer ( String filename, int maxReferralLevel ) {
        this.path = filename;
        this.maxReferralLevel = maxReferralLevel;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Encodable#size()
     */
    @Override
    public int size () {
        return 4 + 2 * this.path.length();
    }


    @Override
    public int encode ( byte[] dst, int dstIndex ) {
        int start = dstIndex;
        SMBUtil.writeInt2(this.maxReferralLevel, dst, dstIndex);
        dstIndex += 2;
        byte[] pathBytes = this.path.getBytes(StandardCharsets.UTF_16LE);
        System.arraycopy(pathBytes, 0, dst, dstIndex, pathBytes.length);
        dstIndex += pathBytes.length;
        SMBUtil.writeInt2(0, dst, dstIndex);
        dstIndex += 2; // null terminator
        return dstIndex - start;
    }
}
