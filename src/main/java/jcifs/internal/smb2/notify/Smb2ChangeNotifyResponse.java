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
package jcifs.internal.smb2.notify;


import java.util.ArrayList;
import java.util.List;

import jcifs.Configuration;
import jcifs.FileNotifyInformation;
import jcifs.internal.NotifyResponse;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.smb1.trans.nt.FileNotifyInformationImpl;
import jcifs.internal.smb2.ServerMessageBlock2Response;
import jcifs.internal.util.SMBUtil;
import jcifs.smb.NtStatus;


/**
 * @author mbechler
 *
 */
public class Smb2ChangeNotifyResponse extends ServerMessageBlock2Response implements NotifyResponse {

    private List<FileNotifyInformation> notifyInformation = new ArrayList<>();


    /**
     * @param config
     */
    public Smb2ChangeNotifyResponse ( Configuration config ) {
        super(config);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#writeBytesWireFormat(byte[], int)
     */
    @Override
    protected int writeBytesWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    /**
     * {@inheritDoc}
     * 
     * @throws SMBProtocolDecodingException
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#readBytesWireFormat(byte[], int)
     */
    @Override
    protected int readBytesWireFormat ( byte[] buffer, int bufferIndex ) throws SMBProtocolDecodingException {
        int start = bufferIndex;

        int structureSize = SMBUtil.readInt2(buffer, bufferIndex);
        if ( structureSize != 9 ) {
            throw new SMBProtocolDecodingException("Expected structureSize = 9");
        }

        int bufferOffset = SMBUtil.readInt2(buffer, bufferIndex + 2) + getHeaderStart();
        bufferIndex += 4;
        int len = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        int elemStart = bufferOffset;
        FileNotifyInformationImpl i = new FileNotifyInformationImpl();
        bufferIndex += i.decode(buffer, bufferOffset, len);
        this.notifyInformation.add(i);

        while ( i.getNextEntryOffset() > 0 && bufferIndex < bufferOffset + len ) {
            bufferIndex = elemStart + i.getNextEntryOffset();
            elemStart = bufferIndex;

            i = new FileNotifyInformationImpl();
            bufferIndex += i.decode(buffer, bufferIndex, len);
            this.notifyInformation.add(i);
        }

        return bufferIndex - start;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.NotifyResponse#getNotifyInformation()
     */
    @Override
    public List<FileNotifyInformation> getNotifyInformation () {
        return this.notifyInformation;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#isErrorResponseStatus()
     */
    @Override
    protected boolean isErrorResponseStatus () {
        return getStatus() != NtStatus.NT_STATUS_NOTIFY_ENUM_DIR && super.isErrorResponseStatus();
    }


}
