/* jcifs smb client library in Java
 * Copyright (C) 2005  "Michael B. Allen" <jcifs at samba dot org>
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


import java.io.IOException;

import jcifs.util.Hexdump;
import jcifs.util.Strings;


public class FileNotifyInformation {

    // filter flags
    public static final int FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001;
    public static final int FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002;
    public static final int FILE_NOTIFY_CHANGE_NAME = 0x00000003;
    public static final int FILE_NOTIFY_CHANGE_ATTRIBUTES = 0x00000004;
    public static final int FILE_NOTIFY_CHANGE_SIZE = 0x00000008;
    public static final int FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010;
    public static final int FILE_NOTIFY_CHANGE_LAST_ACCESS = 0x00000020;
    public static final int FILE_NOTIFY_CHANGE_CREATION = 0x00000040;
    public static final int FILE_NOTIFY_CHANGE_EA = 0x00000080;
    public static final int FILE_NOTIFY_CHANGE_SECURITY = 0x00000100;
    public static final int FILE_NOTIFY_CHANGE_STREAM_NAME = 0x00000200;
    public static final int FILE_NOTIFY_CHANGE_STREAM_SIZE = 0x00000400;
    public static final int FILE_NOTIFY_CHANGE_STREAM_WRITE = 0x00000800;

    // actions returned
    public static final int FILE_ACTION_ADDED = 0x00000001;
    public static final int FILE_ACTION_REMOVED = 0x00000002;
    public static final int FILE_ACTION_MODIFIED = 0x00000003;
    public static final int FILE_ACTION_RENAMED_OLD_NAME = 0x00000004;
    public static final int FILE_ACTION_RENAMED_NEW_NAME = 0x00000005;
    public static final int FILE_ACTION_ADDED_STREAM = 0x00000006;
    public static final int FILE_ACTION_REMOVED_STREAM = 0x00000007;
    public static final int FILE_ACTION_MODIFIED_STREAM = 0x00000008;
    public static final int FILE_ACTION_REMOVED_BY_DELETE = 0x00000009;

    public int nextEntryOffset;
    public int action;
    public int fileNameLength;
    public String fileName;


    public FileNotifyInformation () {}


    public FileNotifyInformation ( byte[] buffer, int bufferIndex, int len ) throws IOException {
        this.decode(buffer, bufferIndex, len);
    }


    public int decode ( byte[] buffer, int bufferIndex, int len ) throws IOException {
        int start = bufferIndex;

        this.nextEntryOffset = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        if ( ( this.nextEntryOffset % 4 ) != 0 ) {
            throw new IOException("Non aligned nextEntryOffset");
        }

        this.action = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        this.fileNameLength = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        this.fileName = Strings.fromUNIBytes(buffer, bufferIndex, this.fileNameLength);
        bufferIndex += this.fileNameLength * 2;
        return bufferIndex - start;
    }


    @Override
    public String toString () {
        String ret = "FileNotifyInformation[nextEntry=" + this.nextEntryOffset + ",action=0x" + Hexdump.toHexString(this.action, 4) + ",file="
                + this.fileName + "]";
        return ret;
    }
}
