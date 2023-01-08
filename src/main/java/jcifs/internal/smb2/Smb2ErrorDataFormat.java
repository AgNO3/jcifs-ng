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
import jcifs.util.Strings;

/**
 * 2.2.2.2 ErrorData format
 * 
 * Defines methods to decode a SMB2 ErrorData format byte array.
 * 
 * @author Gregory Bragg
 */
public class Smb2ErrorDataFormat extends Smb2ErrorContextResponse {

    private boolean absolutePath;
    private int unparsedPathLength;
    private String substituteName;
    private String printName;

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
     * @throws SMBProtocolDecodingException
     */
    public int readSymLinkErrorResponse ( byte[] buffer ) throws SMBProtocolDecodingException {
        int bufferIndex = super.readErrorContextResponse(buffer);
        if ( this.errorId != 0 ) {
            throw new SMBProtocolDecodingException("ErrorId should be 0 for STATUS_STOPPED_ON_SYMLINK");
        }

        // SymLinkLength (4 bytes)
        int symLinkLength = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        // SymLinkErrorTag (4 bytes) (always 0x4C4D5953)
        int symLinkErrorTag = SMBUtil.readInt4(buffer, bufferIndex);
        if ( symLinkErrorTag != 0x4C4D5953 ) {
            throw new SMBProtocolDecodingException("SymLinkErrorTag should be 0x4C4D5953");
        }
        bufferIndex += 4;

        // ReparseTag (4 bytes) (always 0xA000000C)
        int reparseTag = SMBUtil.readInt4(buffer, bufferIndex);
        if ( reparseTag != 0xA000000C ) {
            throw new SMBProtocolDecodingException("ReparseTag should be 0xA000000C");
        }
        bufferIndex += 4;

        // ReparseDataLength (2 bytes)
        int reparsedPathLength = SMBUtil.readInt2(buffer, bufferIndex);
        if ( reparsedPathLength != symLinkLength - 12 ) {
            throw new SMBProtocolDecodingException("ReparseDataLength should be the size of PathBuffer[], in bytes, plus 12");
        }
        bufferIndex += 2; 

        // UnparsedPathLength (2 bytes)
        this.unparsedPathLength = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;

        // SubstituteNameOffset (2 bytes)
        int substituteNameOffset = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;

        // SubstituteNameLength (2 bytes)
        int substituteNameLength = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;

        // PrintNameOffset (2 bytes)
        int printNameOffset = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;

        // PrintNameLength (2 bytes)
        int printNameLength = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;

        // Flags (4 bytes) A 32-bit bit field that specifies whether the substitute is an absolute target path name
        // or a path name relative to the directory containing the symbolic link.
        // We only read the first 2 bytes to get the value, either 0x00000000 or 0x00000001 (0 or 1).
        this.absolutePath = SMBUtil.readInt2(buffer, bufferIndex) == 0;
        bufferIndex += 4;

        // PathBuffer (variable), substitute name
        this.substituteName = Strings.fromUNIBytes(buffer, substituteNameOffset + bufferIndex, substituteNameLength);

        // PathBuffer (variable), print name that also identifies the target of the symbolic link
        this.printName = Strings.fromUNIBytes(buffer, printNameOffset + bufferIndex, printNameLength);

        return symLinkLength;
    }


    public int getErrorDataLength () {
        return this.errorDataLength;
    }


    public int getErrorId () {
        return this.errorId;
    }


    public boolean isAbsolutePath () {
        return this.absolutePath;
    }


    public int getUnparsedPathLength() {
        return this.unparsedPathLength;
    }


    public String getSubstituteName () {
        return this.substituteName;
    }


    public String getPrintName () {
        return this.printName;
    }




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
    public int readShareRedirectErrorContextResponse ( byte[] buffer )
            throws SMBProtocolDecodingException {
        throw new UnsupportedOperationException("Not implemented");
    }

}
