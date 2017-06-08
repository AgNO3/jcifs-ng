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


import jcifs.Configuration;
import jcifs.internal.dfs.DfsReferralResponseBuffer;
import jcifs.internal.smb1.trans.SmbComTransaction;
import jcifs.internal.smb1.trans.SmbComTransactionResponse;


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

    private final DfsReferralResponseBuffer dfsResponse = new DfsReferralResponseBuffer();


    /**
     * 
     * @param config
     */
    public Trans2GetDfsReferralResponse ( Configuration config ) {
        super(config);
        this.setSubCommand(SmbComTransaction.TRANS2_GET_DFS_REFERRAL);
    }


    /**
     * @return the buffer
     */
    public DfsReferralResponseBuffer getDfsResponse () {
        return this.dfsResponse;
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
        bufferIndex += this.dfsResponse.decode(buffer, bufferIndex, len);
        return bufferIndex - start;
    }


    @Override
    public String toString () {
        return new String("Trans2GetDfsReferralResponse[" + super.toString() + ",buffer=" + this.dfsResponse + "]");
    }
}
