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
package jcifs.internal.smb2;


import jcifs.Configuration;
import jcifs.internal.CommonServerMessageBlockRequest;
import jcifs.internal.util.SMBUtil;


/**
 * @author mbechler
 *
 */
public class Smb2CancelRequest extends ServerMessageBlock2 implements CommonServerMessageBlockRequest {

    /**
     * @param config
     * @param mid
     * @param asyncId
     */
    public Smb2CancelRequest ( Configuration config, long mid, long asyncId ) {
        super(config, SMB2_CANCEL);
        setMid(mid);
        setAsyncId(asyncId);
        if ( asyncId != 0 ) {
            addFlags(SMB2_FLAGS_ASYNC_COMMAND);
        }
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Request#getCreditCost()
     */
    @Override
    public int getCreditCost () {
        return 1;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockRequest#isResponseAsync()
     */
    @Override
    public boolean isResponseAsync () {
        return false;
    }


    @Override
    public ServerMessageBlock2Request<?> getNext () {
        return null;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockRequest#getOverrideTimeout()
     */
    @Override
    public Integer getOverrideTimeout () {
        return null;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockRequest#allowChain(jcifs.internal.CommonServerMessageBlockRequest)
     */
    @Override
    public boolean allowChain ( CommonServerMessageBlockRequest next ) {
        return false;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockRequest#split()
     */
    @Override
    public CommonServerMessageBlockRequest split () {
        return null;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockRequest#createCancel()
     */
    @Override
    public CommonServerMessageBlockRequest createCancel () {
        return null;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Request#setRequestCredits(int)
     */
    @Override
    public void setRequestCredits ( int credits ) {
        setCredit(credits);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockRequest#setTid(int)
     */
    @Override
    public void setTid ( int t ) {
        setTreeId(t);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Request#isCancel()
     */
    @Override
    public boolean isCancel () {
        return true;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockRequest#size()
     */
    @Override
    public int size () {
        return size8(Smb2Constants.SMB2_HEADER_LENGTH + 4);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#writeBytesWireFormat(byte[], int)
     */
    @Override
    protected int writeBytesWireFormat ( byte[] dst, int dstIndex ) {
        int start = dstIndex;
        SMBUtil.writeInt2(4, dst, dstIndex);
        dstIndex += 4;
        return dstIndex - start;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#readBytesWireFormat(byte[], int)
     */
    @Override
    protected int readBytesWireFormat ( byte[] buffer, int bufferIndex ) {
        return 0;
    }

}
