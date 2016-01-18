/* jcifs smb client library in Java
 * Copyright (C) 2000  "Michael B. Allen" <jcifs at samba dot org>
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


import jcifs.Configuration;


class Trans2QueryFileInformationResponse extends SmbComTransactionResponse {

    // information levels
    static final int SMB_QUERY_FILE_INTERNAL_INFO = 6;

    private int informationLevel;

    private SmbQueryFileInternalInfo info;

    class SmbQueryFileInternalInfo {

        long indexNumber;


        /**
         * @return the indexNumber
         */
        public long getIndexNumber () {
            return this.indexNumber;
        }


        @Override
        public String toString () {
            return new String("SmbQueryFileInternalInfo[" + "indexNumber=" + this.indexNumber + "]");
        }
    }


    Trans2QueryFileInformationResponse ( Configuration config, int informationLevel ) {
        super(config);
        this.informationLevel = informationLevel;
        this.subCommand = SmbComTransaction.TRANS2_QUERY_PATH_INFORMATION;
    }


    /**
     * @return the info
     */
    public SmbQueryFileInternalInfo getInternalInfo () {
        return this.info;
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
        // observed two zero bytes here with at least win98
        return 2;
    }


    @Override
    int readDataWireFormat ( byte[] buffer, int bufferIndex, int len ) {
        switch ( this.informationLevel ) {
        case SMB_QUERY_FILE_INTERNAL_INFO:
            return readSmbQueryFileInternalInfoWireFormat(buffer, bufferIndex);
        default:
            return 0;
        }
    }


    int readSmbQueryFileInternalInfoWireFormat ( byte[] buffer, int bufferIndex ) {
        int start = bufferIndex;
        SmbQueryFileInternalInfo inf = new SmbQueryFileInternalInfo();
        inf.indexNumber = SMBUtil.readInt8(buffer, bufferIndex);
        this.info = inf;
        return bufferIndex - start;
    }


    @Override
    public String toString () {
        return new String("Trans2QueryFileInformationResponse[" + super.toString() + "]");
    }
}
