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

package jcifs.internal.smb1.trans;


import jcifs.Configuration;
import jcifs.internal.SMBProtocolDecodingException;


/**
 * 
 */
public class TransCallNamedPipeResponse extends SmbComTransactionResponse {

    private final byte[] outputBuffer;


    /**
     * @param config
     * @param inB
     */
    public TransCallNamedPipeResponse ( Configuration config, byte[] inB ) {
        super(config);
        this.outputBuffer = inB;
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
        if ( len > this.outputBuffer.length ) {
            throw new SMBProtocolDecodingException("Payload exceeds buffer size");
        }
        System.arraycopy(buffer, bufferIndex, this.outputBuffer, 0, len);
        return len;
    }


    @Override
    public String toString () {
        return new String("TransCallNamedPipeResponse[" + super.toString() + "]");
    }
}
