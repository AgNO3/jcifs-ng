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
import jcifs.internal.AllocInfo;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.fscc.FileFsFullSizeInformation;
import jcifs.internal.fscc.FileFsSizeInformation;
import jcifs.internal.fscc.FileSystemInformation;
import jcifs.internal.fscc.SmbInfoAllocation;
import jcifs.internal.smb1.trans.SmbComTransaction;
import jcifs.internal.smb1.trans.SmbComTransactionResponse;


/**
 * 
 */
public class Trans2QueryFSInformationResponse extends SmbComTransactionResponse {

    private int informationLevel;
    private FileSystemInformation info;


    /**
     * 
     * @param config
     * @param informationLevel
     */
    public Trans2QueryFSInformationResponse ( Configuration config, int informationLevel ) {
        super(config);
        this.informationLevel = informationLevel;
        this.setCommand(SMB_COM_TRANSACTION2);
        this.setSubCommand(SmbComTransaction.TRANS2_QUERY_FS_INFORMATION);
    }


    /**
     * @return the informationLevel
     */
    public int getInformationLevel () {
        return this.informationLevel;
    }


    /**
     * @return the filesystem info
     */
    public FileSystemInformation getInfo () {
        return this.info;
    }


    /**
     * @param clazz
     * @return the filesystem info
     * @throws CIFSException
     */
    @SuppressWarnings ( "unchecked" )
    public <T extends FileSystemInformation> T getInfo ( Class<T> clazz ) throws CIFSException {
        if ( !clazz.isAssignableFrom(this.info.getClass()) ) {
            throw new CIFSException("Incompatible file information class");
        }
        return (T) getInfo();
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
    protected int readDataWireFormat ( byte[] buffer, int bufferIndex, int len ) throws SMBProtocolDecodingException {
        int start = bufferIndex;
        AllocInfo inf = createInfo();
        if ( inf != null ) {
            bufferIndex += inf.decode(buffer, bufferIndex, getDataCount());
            this.info = inf;
        }
        return bufferIndex - start;
    }


    /**
     * @return
     */
    private AllocInfo createInfo () {
        AllocInfo inf;
        switch ( this.informationLevel ) {
        case FileSystemInformation.SMB_INFO_ALLOCATION:
            inf = new SmbInfoAllocation();
            break;
        case FileSystemInformation.FS_SIZE_INFO:
            inf = new FileFsSizeInformation();
            break;
        case FileSystemInformation.FS_FULL_SIZE_INFO:
            inf = new FileFsFullSizeInformation();
            break;
        default:
            return null;
        }
        return inf;
    }


    @Override
    public String toString () {
        return new String("Trans2QueryFSInformationResponse[" + super.toString() + "]");
    }

}
