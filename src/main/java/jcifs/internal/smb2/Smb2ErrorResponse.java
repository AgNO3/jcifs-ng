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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.util.SMBUtil;
import jcifs.util.Strings;

/**
 * 
 * @author Gregory Bragg
 */
public class Smb2ErrorResponse {

    private static Logger log = LoggerFactory.getLogger(Smb2ErrorResponse.class);

    private int errorDataLengthLength;
    private int errorId;

    private boolean absolutePath;
    private String substituteName;
    private String printName;

    /**
     * 2.2.2.1 SMB2 ERROR Context Response
     * 
     * @param buffer
     * @return The length, in bytes, of the response including the variable-length portion and excluding SymLinkLength
     * @throws Smb2ProtocolDecodingException
     */
    public int readSymLinkErrorContextResponse ( byte[] buffer ) throws SMBProtocolDecodingException {
        // start at the beginning of the 8-byte aligned boundary
        // for the SMB2 ERROR Context structure
        int bufferIndex = 0;

        // ErrorDataLength (4 bytes)
        this.errorDataLengthLength = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        // ErrorId (4 bytes), for STATUS_STOPPED_ON_SYMLINK this is always 0x00000000
        this.errorId = SMBUtil.readInt4(buffer, bufferIndex);
        if ( this.errorId != 0 ) {
            throw new SMBProtocolDecodingException("ErrorId should be 0 for STATUS_STOPPED_ON_SYMLINK");
        }
        bufferIndex += 4;

        return this.readSymLinkErrorResponse( buffer, bufferIndex );
    }
    
    /**
     * 2.2.2.2.1 Symbolic Link Error Response
     * 
     * @param buffer
     * @param bufferIndex
     * @return The length, in bytes, of the response including the variable-length portion and excluding SymLinkLength
     * @throws Smb2ProtocolDecodingException
     */
    protected int readSymLinkErrorResponse ( byte[] buffer, int bufferIndex ) throws SMBProtocolDecodingException {
        // SymLinkLength (4 bytes)
        int symLinkLength = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        // SymLinkErrorTag (4 bytes) (always 0x4C4D5953)
        int symLinkErrorTag = SMBUtil.readInt4(buffer, bufferIndex);
        log.info("symLinkErrorTag -> {}", symLinkErrorTag);
        if ( !Integer.toHexString(symLinkErrorTag).toUpperCase().equals("4C4D5953") ) {
            throw new SMBProtocolDecodingException("SymLinkErrorTag should be 0x4C4D5953");
        }
        bufferIndex += 4;

        // skip, not needed
        bufferIndex += 4; // ReparseTag (4 bytes) (always 0xA000000C)
        bufferIndex += 2; // ReparseDataLength (2 bytes)

        // UnparsedPathLength (2 bytes)
        int unparsedPathLength = SMBUtil.readInt2(buffer, bufferIndex);
        log.info("unparsedPathLength -> {}", unparsedPathLength);
        bufferIndex += 2;

        // SubstituteNameOffset (2 bytes)
        int substituteNameOffset = SMBUtil.readInt2(buffer, bufferIndex);
        log.info("substituteNameOffset -> {}", substituteNameOffset);
        bufferIndex += 2;

        // SubstituteNameLength (2 bytes)
        int substituteNameLength = SMBUtil.readInt2(buffer, bufferIndex);
        log.info("substituteNameLength -> {}", substituteNameLength);
        bufferIndex += 2;

        // PrintNameOffset (2 bytes)
        int printNameOffset = SMBUtil.readInt2(buffer, bufferIndex);
        log.info("printNameOffset -> {}", printNameOffset);
        bufferIndex += 2;

        // PrintNameLength (2 bytes)
        int printNameLength = SMBUtil.readInt2(buffer, bufferIndex);
        log.info("printNameLength -> {}", printNameLength);
        bufferIndex += 2;

        // Flags (4 bytes)
        this.absolutePath = SMBUtil.readInt4(buffer, bufferIndex) == 0;
        log.info("absolutePath -> {}", this.absolutePath);
        bufferIndex += 4;

        // PathBuffer (variable), substitute name
        this.substituteName = Strings.fromUNIBytes(buffer, substituteNameOffset + bufferIndex, substituteNameLength);
        log.info("substituteName -> {}", this.substituteName);

        // PathBuffer (variable), print name that also identifies the target of the symbolic link
        this.printName = Strings.fromUNIBytes(buffer, printNameOffset + bufferIndex, printNameLength);
        log.info("printName -> {}", this.printName);

        return symLinkLength;
    }

    public int getErrorDataLengthLength () {
        return this.errorDataLengthLength;
    }

    public int getErrorId () {
        return this.errorId;
    }

    public boolean isAbsolutePath () {
        return this.absolutePath;
    }

    public String getSubstituteName () {
        return this.substituteName;
    }

    public String getPrintName () {
        return this.printName;
    }

}
