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


import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import jcifs.Configuration;
import jcifs.RuntimeCIFSException;


class Trans2GetDfsReferralResponse extends SmbComTransactionResponse {

    public static final int FLAGS_NAME_LIST_REFERRAL = 0x0002;
    public static final int FLAGS_TARGET_SET_BOUNDARY = 0x0004;
    public static final int TYPE_ROOT_TARGETS = 0x0;
    public static final int TYPE_NON_ROOT_TARGETS = 0x1;

    class Referral {

        int version;
        int size;
        int serverType;
        int rflags;
        int proximity;
        String altPath;

        int ttl;
        String rpath = null;
        String node = null;
        String specialName = null;

        String[] expandedNames = new String[0];


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

                if ( ( this.rflags & FLAGS_NAME_LIST_REFERRAL ) == 0 ) {
                    int pathOffset = SMBUtil.readInt2(buffer, bufferIndex);
                    bufferIndex += 2;
                    int altPathOffset = SMBUtil.readInt2(buffer, bufferIndex);
                    bufferIndex += 2;
                    int nodeOffset = SMBUtil.readInt2(buffer, bufferIndex);
                    bufferIndex += 2;

                    if ( pathOffset > 0 ) {
                        this.rpath = readString(buffer, start + pathOffset, len, unicode);
                    }
                    if ( nodeOffset > 0 ) {
                        this.node = readString(buffer, start + nodeOffset, len, unicode);
                    }
                    if ( altPathOffset > 0 ) {
                        this.altPath = readString(buffer, start + altPathOffset, len, unicode);
                    }
                }
                else {
                    int specialNameOffset = SMBUtil.readInt2(buffer, bufferIndex);
                    bufferIndex += 2;
                    int numExpanded = SMBUtil.readInt2(buffer, bufferIndex);
                    bufferIndex += 2;
                    int expandedNameOffset = SMBUtil.readInt2(buffer, bufferIndex);
                    bufferIndex += 2;

                    if ( specialNameOffset > 0 ) {
                        this.specialName = readString(buffer, start + specialNameOffset, len, unicode);
                    }

                    if ( expandedNameOffset > 0 ) {
                        List<String> names = new ArrayList<>();
                        for ( int i = 0; i < numExpanded; i++ ) {
                            String en = readString(buffer, start + expandedNameOffset, len, unicode);
                            names.add(en);
                            expandedNameOffset += stringWireLength(en, start + expandedNameOffset);
                        }
                        this.expandedNames = names.toArray(new String[names.size()]);
                    }

                }
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
                        + ",proximity=" + this.proximity + ",ttl=" + this.ttl + ",path=" + this.rpath + ",altPath=" + this.altPath + ",node="
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
        this.forceUnicode = true;
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
