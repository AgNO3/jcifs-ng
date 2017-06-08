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


import java.util.Arrays;

import jcifs.Decodable;
import jcifs.internal.util.SMBUtil;


/**
 * @author mbechler
 *
 */
public class DfsReferralResponseBuffer implements Decodable {

    private int pathConsumed;
    private int numReferrals;
    private int tflags;
    private Referral[] referrals;


    /**
     * @return the pathConsumed
     */
    public final int getPathConsumed () {
        return this.pathConsumed;
    }


    /**
     * @return the numReferrals
     */
    public final int getNumReferrals () {
        return this.numReferrals;
    }


    /**
     * @return the tflags
     */
    public final int getTflags () {
        return this.tflags;
    }


    /**
     * @return the referrals
     */
    public final Referral[] getReferrals () {
        return this.referrals;
    }


    @Override
    public int decode ( byte[] buffer, int bufferIndex, int len ) {
        int start = bufferIndex;

        this.pathConsumed = SMBUtil.readInt2(buffer, bufferIndex) / 2;
        bufferIndex += 2;
        this.numReferrals = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.tflags = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 4;

        this.referrals = new Referral[this.numReferrals];
        for ( int ri = 0; ri < this.numReferrals; ri++ ) {
            this.referrals[ ri ] = new Referral();
            bufferIndex += this.referrals[ ri ].decode(buffer, bufferIndex, len);
        }

        return bufferIndex - start;
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString () {
        return "pathConsumed=" + this.pathConsumed + ",numReferrals=" + this.numReferrals + ",flags=" + this.tflags + ",referrals="
                + Arrays.toString(this.referrals);
    }
}
