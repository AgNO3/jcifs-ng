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


import jcifs.Configuration;
import jcifs.internal.smb1.trans.SmbComTransaction;
import jcifs.internal.smb1.trans.SmbComTransactionResponse;
import jcifs.internal.util.SMBUtil;
import jcifs.util.Strings;


/**
 * 
 */
public class Trans2FindFirst2Response extends SmbComTransactionResponse {

    // information levels

    static final int SMB_INFO_STANDARD = 1;
    static final int SMB_INFO_QUERY_EA_SIZE = 2;
    static final int SMB_INFO_QUERY_EAS_FROM_LIST = 3;
    static final int SMB_FIND_FILE_DIRECTORY_INFO = 0x101;
    static final int SMB_FIND_FILE_FULL_DIRECTORY_INFO = 0x102;
    static final int SMB_FILE_NAMES_INFO = 0x103;
    static final int SMB_FILE_BOTH_DIRECTORY_INFO = 0x104;

    private int sid;
    private boolean isEndOfSearch;
    private int eaErrorOffset;
    private int lastNameOffset, lastNameBufferIndex;
    private String lastName;
    private int resumeKey;


    /**
     * 
     * @param config
     */
    public Trans2FindFirst2Response ( Configuration config ) {
        super(config, SMB_COM_TRANSACTION2, SmbComTransaction.TRANS2_FIND_FIRST2);
    }


    /**
     * @return the sid
     */
    public final int getSid () {
        return this.sid;
    }


    /**
     * @return the isEndOfSearch
     */
    public final boolean isEndOfSearch () {
        return this.isEndOfSearch;
    }


    /**
     * @return the lastName
     */
    public final String getLastName () {
        return this.lastName;
    }


    /**
     * @return the resumeKey
     */
    public final int getResumeKey () {
        return this.resumeKey;
    }


    String readString ( byte[] src, int srcIndex, int len ) {
        String str = null;
        if ( isUseUnicode() ) {
            // should Unicode alignment be corrected for here?
            str = Strings.fromUNIBytes(src, srcIndex, len);
        }
        else {

            /*
             * On NT without Unicode the fileNameLength
             * includes the '\0' whereas on win98 it doesn't. I
             * guess most clients only support non-unicode so
             * they don't run into this.
             */

            /*
             * UPDATE: Maybe not! Could this be a Unicode alignment issue. I hope
             * so. We cannot just comment out this method and use readString of
             * ServerMessageBlock.java because the arguments are different, however
             * one might be able to reduce this.
             */

            if ( len > 0 && src[ srcIndex + len - 1 ] == '\0' ) {
                len--;
            }
            str = Strings.fromOEMBytes(src, srcIndex, len, getConfig());
        }
        return str;
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
        int start = bufferIndex;

        if ( this.getSubCommand() == SmbComTransaction.TRANS2_FIND_FIRST2 ) {
            this.sid = SMBUtil.readInt2(buffer, bufferIndex);
            bufferIndex += 2;
        }
        this.setNumEntries(SMBUtil.readInt2(buffer, bufferIndex));
        bufferIndex += 2;
        this.isEndOfSearch = ( buffer[ bufferIndex ] & 0x01 ) == 0x01 ? true : false;
        bufferIndex += 2;
        this.eaErrorOffset = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.lastNameOffset = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;

        return bufferIndex - start;
    }


    @Override
    protected int readDataWireFormat ( byte[] buffer, int bufferIndex, int len ) {
        SmbFindFileBothDirectoryInfo e;

        this.lastNameBufferIndex = bufferIndex + this.lastNameOffset;

        SmbFindFileBothDirectoryInfo[] results = new SmbFindFileBothDirectoryInfo[getNumEntries()];
        for ( int i = 0; i < getNumEntries(); i++ ) {
            results[ i ] = e = new SmbFindFileBothDirectoryInfo();

            e.nextEntryOffset = SMBUtil.readInt4(buffer, bufferIndex);
            e.fileIndex = SMBUtil.readInt4(buffer, bufferIndex + 4);
            e.creationTime = SMBUtil.readTime(buffer, bufferIndex + 8);
            // e.lastAccessTime = readTime( buffer, bufferIndex + 16 );
            e.lastWriteTime = SMBUtil.readTime(buffer, bufferIndex + 24);
            // e.changeTime = readTime( buffer, bufferIndex + 32 );
            e.endOfFile = SMBUtil.readInt8(buffer, bufferIndex + 40);
            // e.allocationSize = readInt8( buffer, bufferIndex + 48 );
            e.extFileAttributes = SMBUtil.readInt4(buffer, bufferIndex + 56);
            e.fileNameLength = SMBUtil.readInt4(buffer, bufferIndex + 60);
            // e.eaSize = readInt4( buffer, bufferIndex + 64 );
            // e.shortNameLength = buffer[bufferIndex + 68] & 0xFF;

            /*
             * With NT, the shortName is in Unicode regardless of what is negotiated.
             */

            // e.shortName = readString( buffer, bufferIndex + 70, e.shortNameLength );
            e.filename = readString(buffer, bufferIndex + 94, e.fileNameLength);

            /*
             * lastNameOffset ends up pointing to either to
             * the exact location of the filename(e.g. Win98)
             * or to the start of the entry containing the
             * filename(e.g. NT). Ahhrg! In either case the
             * lastNameOffset falls between the start of the
             * entry and the next entry.
             */

            if ( this.lastNameBufferIndex >= bufferIndex
                    && ( e.nextEntryOffset == 0 || this.lastNameBufferIndex < ( bufferIndex + e.nextEntryOffset ) ) ) {
                this.lastName = e.filename;
                this.resumeKey = e.fileIndex;
            }

            bufferIndex += e.nextEntryOffset;
        }

        setResults(results);

        /*
         * last nextEntryOffset for NT 4(but not 98) is 0 so we must
         * use dataCount or our accounting will report an error for NT :~(
         */
        return getDataCount();
    }


    @Override
    public String toString () {
        String c;
        if ( this.getSubCommand() == SmbComTransaction.TRANS2_FIND_FIRST2 ) {
            c = "Trans2FindFirst2Response[";
        }
        else {
            c = "Trans2FindNext2Response[";
        }
        return new String(
            c + super.toString() + ",sid=" + this.sid + ",searchCount=" + getNumEntries() + ",isEndOfSearch=" + this.isEndOfSearch + ",eaErrorOffset="
                    + this.eaErrorOffset + ",lastNameOffset=" + this.lastNameOffset + ",lastName=" + this.lastName + "]");
    }
}
