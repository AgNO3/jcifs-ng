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

package jcifs.smb;


import java.util.Arrays;

import jcifs.Configuration;
import jcifs.RuntimeCIFSException;
import jcifs.SmbConstants;


class Trans2GetDfsReferralResponse extends SmbComTransactionResponse {

    class Referral {

        private int version;
        private int size;
        private int serverType;
        private int rflags;
        private int proximity;
        private int pathOffset;
        private int altPathOffset;
        private int nodeOffset;
        private String altPath;

        int ttl;
        String rpath = null;
        String node = null;


        int readWireFormat ( byte[] buffer, int bufferIndex, int len, boolean unicode ) {
            int start = bufferIndex;

            this.version = SMBUtil.readInt2(buffer, bufferIndex);
            if ( this.version != 3 && this.version != 1 ) {
                throw new RuntimeCIFSException("Version " + this.version + " referral not supported. Please report this to jcifs at samba dot org.");
            }
            bufferIndex += 2;
            this.size = SMBUtil.readInt2(buffer, bufferIndex);
            bufferIndex += 2;
            this.serverType = SMBUtil.readInt2(buffer, bufferIndex);
            bufferIndex += 2;
            this.rflags = SMBUtil.readInt2(buffer, bufferIndex);
            bufferIndex += 2;
            if ( this.version == 3 ) {
                this.proximity = SMBUtil.readInt2(buffer, bufferIndex);
                bufferIndex += 2;
                this.ttl = SMBUtil.readInt2(buffer, bufferIndex);
                bufferIndex += 2;
                this.pathOffset = SMBUtil.readInt2(buffer, bufferIndex);
                bufferIndex += 2;
                this.altPathOffset = SMBUtil.readInt2(buffer, bufferIndex);
                bufferIndex += 2;
                this.nodeOffset = SMBUtil.readInt2(buffer, bufferIndex);
                bufferIndex += 2;

                this.rpath = readString(buffer, start + this.pathOffset, len, unicode);
                if ( this.nodeOffset > 0 )
                    this.node = readString(buffer, start + this.nodeOffset, len, unicode);
            }
            else if ( this.version == 1 ) {
                this.node = readString(buffer, bufferIndex, len, unicode);
            }

            return this.size;
        }


        @Override
        public String toString () {
            return new String(
                "Referral[" + "version=" + this.version + ",size=" + this.size + ",serverType=" + this.serverType + ",flags=" + this.rflags
                        + ",proximity=" + this.proximity + ",ttl=" + this.ttl + ",pathOffset=" + this.pathOffset + ",altPathOffset="
                        + this.altPathOffset + ",nodeOffset=" + this.nodeOffset + ",path=" + this.rpath + ",altPath=" + this.altPath + ",node="
                        + this.node + "]");
        }
    }

    int pathConsumed;
    int numReferrals;
    int tflags;
    Referral[] referrals;


    Trans2GetDfsReferralResponse ( Configuration config ) {
        super(config);
        this.subCommand = SmbComTransaction.TRANS2_GET_DFS_REFERRAL;
    }


    @Override
    int writeSetupWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    int writeParametersWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    int writeDataWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    int readSetupWireFormat ( byte[] buffer, int bufferIndex, int len ) {
        return 0;
    }


    @Override
    int readParametersWireFormat ( byte[] buffer, int bufferIndex, int len ) {
        return 0;
    }


    @Override
    int readDataWireFormat ( byte[] buffer, int bufferIndex, int len ) {
        int start = bufferIndex;

        this.pathConsumed = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;

        boolean unicode = ( this.flags2 & SmbConstants.FLAGS2_UNICODE ) != 0;
        /*
         * Samba 2.2.8a will reply with Unicode paths even though
         * ASCII is negotiated so we must use flags2 (probably
         * should anyway).
         * 
         * No, samba will always send unicode
         */
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
            bufferIndex += this.referrals[ ri ].readWireFormat(buffer, bufferIndex, len, unicode);
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
