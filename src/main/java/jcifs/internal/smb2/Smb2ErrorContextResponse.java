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
    protected int readErrorContextResponse(byte[] buffer) {
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

    /**
     * 2.2.2.2.1 Symbolic Link Error Response
     * 
     * The Symbolic Link Error Response is used to indicate that a symbolic link was encountered on
     * create; it describes the target path that the client MUST use if it requires to follow the
     * symbolic link. This structure is contained in the ErrorData section of the SMB2 ERROR
     * Response (section 2.2.2). This structure MUST NOT be returned in an SMB2 ERROR Response
     * unless the Status code in the header of that response is set to STATUS_STOPPED_ON_SYMLINK.
     * 
     * @param buffer
     * @return The length, in bytes, of the response
     * @throws Smb2ProtocolDecodingException
     */
    public abstract int readSymLinkErrorResponse ( byte[] buffer ) throws SMBProtocolDecodingException;

    /**
     * 2.2.2.2.2 Share Redirect Error Context Response
     * 
     * Servers which negotiate SMB 3.1.1 or higher can return this error context to a client in
     * response to a tree connect request with the SMB2_TREE_CONNECT_FLAG_REDIRECT_TO_OWNER bit set
     * in the Flags field of the SMB2 TREE_CONNECT request. The corresponding Status code in the
     * SMB2 header of the response MUST be set to STATUS_BAD_NETWORK_NAME. The error context data is
     * formatted as follows.
     * 
     * @param buffer
     * @return The length, in bytes, of the response
     * @throws SMBProtocolDecodingException
     */
    public abstract int readShareRedirectErrorContextResponse ( byte[] buffer ) throws SMBProtocolDecodingException;

}
