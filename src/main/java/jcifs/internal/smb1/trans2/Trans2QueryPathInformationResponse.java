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

package jcifs.internal.smb1.trans2;


import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.fscc.FileBasicInfo;
import jcifs.internal.fscc.FileInformation;
import jcifs.internal.fscc.FileInternalInfo;
import jcifs.internal.fscc.FileStandardInfo;
import jcifs.internal.smb1.trans.SmbComTransaction;
import jcifs.internal.smb1.trans.SmbComTransactionResponse;


/**
 * 
 */
public class Trans2QueryPathInformationResponse extends SmbComTransactionResponse {

    private final int informationLevel;
    private FileInformation info;


    /**
     * 
     * @param config
     * @param informationLevel
     */
    public Trans2QueryPathInformationResponse ( Configuration config, int informationLevel ) {
        super(config);
        this.informationLevel = informationLevel;
        this.setSubCommand(SmbComTransaction.TRANS2_QUERY_PATH_INFORMATION);
    }


    /**
     * @return the info
     */
    public final FileInformation getInfo () {
        return this.info;
    }


    /**
     * 
     * @param type
     * @return the info
     * @throws CIFSException
     */
    @SuppressWarnings ( "unchecked" )
    public <T extends FileInformation> T getInfo ( Class<T> type ) throws CIFSException {
        if ( !type.isAssignableFrom(this.info.getClass()) ) {
            throw new CIFSException("Incompatible file information class");
        }
        return (T) this.info;
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
        // observed two zero bytes here with at least win98
        return 2;
    }


    @Override
    protected int readDataWireFormat ( byte[] buffer, int bufferIndex, int len ) throws SMBProtocolDecodingException {
        int start = bufferIndex;
        FileInformation inf = createFileInformation();
        if ( inf != null ) {
            bufferIndex += inf.decode(buffer, bufferIndex, getDataCount());
            this.info = inf;
        }
        return bufferIndex - start;
    }


    private FileInformation createFileInformation () {
        FileInformation inf;
        switch ( this.informationLevel ) {
        case FileInformation.FILE_BASIC_INFO:
            inf = new FileBasicInfo();
            break;
        case FileInformation.FILE_STANDARD_INFO:
            inf = new FileStandardInfo();
            break;
        case FileInformation.FILE_INTERNAL_INFO:
            inf = new FileInternalInfo();
            break;
        default:
            return null;
        }
        return inf;
    }


    @Override
    public String toString () {
        return new String("Trans2QueryPathInformationResponse[" + super.toString() + "]");
    }
}
