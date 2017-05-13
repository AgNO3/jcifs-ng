/* jcifs smb client library in Java
 * Copyright (C) 2003  "Michael B. Allen" <jcifs at samba dot org>
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

package jcifs.internal.smb1.trans2;


import java.util.Arrays;

import jcifs.Configuration;
import jcifs.internal.smb1.trans.SmbComTransaction;
import jcifs.internal.smb1.trans.SmbComTransactionResponse;
import jcifs.internal.util.SMBUtil;


/**
 * 
 */
public class Trans2GetDfsReferralResponse extends SmbComTransactionResponse {

    /**
     * 
     */
    public static final int FLAGS_NAME_LIST_REFERRAL = 0x0002;
    /**
     * 
     */
    public static final int FLAGS_TARGET_SET_BOUNDARY = 0x0004;
    /**
     * 
     */
    public static final int TYPE_ROOT_TARGETS = 0x0;
    /**
     * 
     */
    public static final int TYPE_NON_ROOT_TARGETS = 0x1;

    private int pathConsumed;
    private int numReferrals;
    private int tflags;
    private Referral[] referrals;


    /**
     * 
     * @param config
     */
    public Trans2GetDfsReferralResponse ( Configuration config ) {
        super(config);
        this.setSubCommand(SmbComTransaction.TRANS2_GET_DFS_REFERRAL);
    }


    /**
     * @return the pathConsumed
     */
    public int getPathConsumed () {
        return this.pathConsumed;
    }


    /**
     * @return the numReferrals
     */
    public int getNumReferrals () {
        return this.numReferrals;
    }


    /**
     * @return the tflags
     */
    public int getTFlags () {
        return this.tflags;
    }


    /**
     * @return the referrals
     */
    public Referral[] getReferrals () {
        return this.referrals;
    }


    @Override
    public boolean isForceUnicode () {
        return true;
    }


    @Override
    protected int writeSetupWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    protected int writeParametersWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    protected int writeDataWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    protected int readSetupWireFormat ( byte[] buffer, int bufferIndex, int len ) {
        return 0;
    }


    @Override
    protected int readParametersWireFormat ( byte[] buffer, int bufferIndex, int len ) {
        return 0;
    }


    @Override
    protected int readDataWireFormat ( byte[] buffer, int bufferIndex, int len ) {
        int start = bufferIndex;

        this.pathConsumed = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;

        /*
         * old:
         * Samba 2.2.8a will reply with Unicode paths even though
         * ASCII is negotiated so we must use flags2 (probably
         * should anyway).
         * 
         * No, TRANS2_GET_DFS_REFERRAL just does not seem to allow non unicode requests,
         * (at least recent) windows servers will reply with incorrect function if unicode flag2 is not set.
         */
        boolean unicode = true;
        if ( unicode ) {
            this.pathConsumed /= 2;
        }
        this.numReferrals = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.tflags = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 4;

        this.referrals = new Referral[this.numReferrals];
        for ( int ri = 0; ri < this.numReferrals; ri++ ) {
            this.referrals[ ri ] = new Referral();
            bufferIndex += this.referrals[ ri ].readWireFormat(this, buffer, bufferIndex, len, unicode);
        }

        return bufferIndex - start;
    }


    @Override
    public String toString () {
        return new String(
            "Trans2GetDfsReferralResponse[" + super.toString() + ",pathConsumed=" + this.pathConsumed + ",numReferrals=" + this.numReferrals
                    + ",flags=" + this.tflags + "]:\n " + Arrays.toString(this.referrals));
    }
}
