/*
 * © 2022 AgNO3 Gmbh & Co. KG
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

import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.util.SMBUtil;

/**
 * 2.2.2.1 SMB2 ERROR Context Response
 * 
 * Defines methods to decode a SMB2 Error Context Response byte array.
 * 
 * @author Gregory Bragg
 */
public abstract class Smb2ErrorContextResponse {

    protected int errorDataLength;
    protected int errorId;

    /**
     * 2.2.2.1 SMB2 ERROR Context Response
     * 
     * For the SMB dialect 3.1.1, the servers format the error data as an array of SMB2 ERROR Context
     * structures. Each error context is a variable-length structure that contains an identifier for
     * the error context followed by the error data.
     * 
     * Each SMB2 ERROR Context MUST start at an 8-byte aligned boundary relative to the start of the
     * SMB2 ERROR Response. Otherwise, it SHOULD be formatted as specified in section 2.2.2.2.
     * 
     * This method must be called first in any of the methods implemented by the subclasses.
     * 
     * @param buffer
     * @return The length, in bytes, of the response including the variable-length portion
     * @throws Smb2ProtocolDecodingException
     */
    protected int readErrorContextResponse ( byte[] buffer ) {
        // start at the beginning of the 8-byte aligned boundary
        // for the SMB2 ERROR Context structure
        int bufferIndex = 0;

        // ErrorDataLength (4 bytes)
        this.errorDataLength = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        // ErrorId (4 bytes)
        this.errorId = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        return bufferIndex;
    }



}
