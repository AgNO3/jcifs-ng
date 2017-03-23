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

package jcifs.smb;


import java.util.Date;

import jcifs.Configuration;
import jcifs.SmbConstants;
import jcifs.util.Strings;


class Trans2FindFirst2Response extends SmbComTransactionResponse {

    // information levels

    static final int SMB_INFO_STANDARD = 1;
    static final int SMB_INFO_QUERY_EA_SIZE = 2;
    static final int SMB_INFO_QUERY_EAS_FROM_LIST = 3;
    static final int SMB_FIND_FILE_DIRECTORY_INFO = 0x101;
    static final int SMB_FIND_FILE_FULL_DIRECTORY_INFO = 0x102;
    static final int SMB_FILE_NAMES_INFO = 0x103;
    static final int SMB_FILE_BOTH_DIRECTORY_INFO = 0x104;

    class SmbFindFileBothDirectoryInfo implements FileEntry {

        int nextEntryOffset;
        int fileIndex;
        long creationTime;
        long lastAccessTime;
        long lastWriteTime;
        long changeTime;
        long endOfFile;
        long allocationSize;
        int extFileAttributes;
        int fileNameLength;
        int eaSize;
        int shortNameLength;
        String shortName;
        String filename;


        @Override
        public String getName () {
            return this.filename;
        }


        @Override
        public int getType () {
            return SmbConstants.TYPE_FILESYSTEM;
        }


        @Override
        public int getAttributes () {
            return this.extFileAttributes;
        }


        @Override
        public long createTime () {
            return this.creationTime;
        }


        @Override
        public long lastModified () {
            return this.lastWriteTime;
        }


        @Override
        public long lastAccess () {
            return this.lastAccessTime;
        }


        @Override
        public long length () {
            return this.endOfFile;
        }


        @Override
        public String toString () {
            return new String(
                "SmbFindFileBothDirectoryInfo[" + "nextEntryOffset=" + this.nextEntryOffset + ",fileIndex=" + this.fileIndex + ",creationTime="
                        + new Date(this.creationTime) + ",lastAccessTime=" + new Date(this.lastAccessTime) + ",lastWriteTime="
                        + new Date(this.lastWriteTime) + ",changeTime=" + new Date(this.changeTime) + ",endOfFile=" + this.endOfFile
                        + ",allocationSize=" + this.allocationSize + ",extFileAttributes=" + this.extFileAttributes + ",fileNameLength="
                        + this.fileNameLength + ",eaSize=" + this.eaSize + ",shortNameLength=" + this.shortNameLength + ",shortName=" + this.shortName
                        + ",filename=" + this.filename + "]");
        }
    }

    int sid;
    boolean isEndOfSearch;
    int eaErrorOffset;
    int lastNameOffset, lastNameBufferIndex;
    String lastName;
    int resumeKey;


    Trans2FindFirst2Response ( Configuration config ) {
        super(config);
        this.command = SMB_COM_TRANSACTION2;
        this.subCommand = SmbComTransaction.TRANS2_FIND_FIRST2;
    }


    String readString ( byte[] src, int srcIndex, int len ) {
        String str = null;
        if ( this.useUnicode ) {
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
    int writeSetupWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    int writeParametersWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    int writeDataWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    int readSetupWireFormat ( byte[] buffer, int bufferIndex, int len ) {
        return 0;
    }


    @Override
    int readParametersWireFormat ( byte[] buffer, int bufferIndex, int len ) {
        int start = bufferIndex;

        if ( this.subCommand == SmbComTransaction.TRANS2_FIND_FIRST2 ) {
            this.sid = SMBUtil.readInt2(buffer, bufferIndex);
            bufferIndex += 2;
        }
        this.numEntries = SMBUtil.readInt2(buffer, bufferIndex);
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
    int readDataWireFormat ( byte[] buffer, int bufferIndex, int len ) {
        SmbFindFileBothDirectoryInfo e;

        this.lastNameBufferIndex = bufferIndex + this.lastNameOffset;

        this.results = new SmbFindFileBothDirectoryInfo[this.numEntries];
        for ( int i = 0; i < this.numEntries; i++ ) {
            this.results[ i ] = e = new SmbFindFileBothDirectoryInfo();

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

        /*
         * last nextEntryOffset for NT 4(but not 98) is 0 so we must
         * use dataCount or our accounting will report an error for NT :~(
         */
        return this.dataCount;
    }


    @Override
    public String toString () {
        String c;
        if ( this.subCommand == SmbComTransaction.TRANS2_FIND_FIRST2 ) {
            c = "Trans2FindFirst2Response[";
        }
        else {
            c = "Trans2FindNext2Response[";
        }
        return new String(
            c + super.toString() + ",sid=" + this.sid + ",searchCount=" + this.numEntries + ",isEndOfSearch=" + this.isEndOfSearch + ",eaErrorOffset="
                    + this.eaErrorOffset + ",lastNameOffset=" + this.lastNameOffset + ",lastName=" + this.lastName + "]");
    }
}
