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


import org.apache.log4j.Logger;

import jcifs.Configuration;
import jcifs.RuntimeCIFSException;
import jcifs.SmbConstants;
import jcifs.util.Hexdump;
import jcifs.util.Strings;
import jcifs.util.transport.Request;
import jcifs.util.transport.Response;


abstract class ServerMessageBlock2 extends Response implements Request {

    private static final Logger log = Logger.getLogger(ServerMessageBlock2.class);

    /*
     * These are all the smbs supported by this library. This includes requests
     * and well as their responses for each type however the actuall implementations
     * of the readXxxWireFormat and writeXxxWireFormat methods may not be in
     * place. For example at the time of this writing the readXxxWireFormat
     * for requests and the writeXxxWireFormat for responses are not implemented
     * and simply return 0. These would need to be completed for a server
     * implementation.
     */

    static final short SMB2_NEGOTIATE = 0x00;
    static final short SMB2_SESSION_SETUP = 0x01;
    static final short SMB2_LOGOFF = 0x02;
    static final short SMB2_TREE_CONNECT = 0x0003;
    static final short SMB2_TREE_DISCONNECT = 0x0004;
    static final short SMB2_CREATE = 0x0005;
    static final short SMB2_CLOSE = 0x0006;
    static final short SMB2_FLUSH = 0x0007;
    static final short SMB2_READ = 0x0008;
    static final short SMB2_WRITE = 0x0009;
    static final short SMB2_LOCK = 0x000A;
    static final short SMB2_IOCTL = 0x000B;
    static final short SMB2_CANCEL = 0x000C;
    static final short SMB2_ECHO = 0x000D;
    static final short SMB2_QUERY_DIRECTORY = 0x000E;
    static final short SMB2_CHANGE_NOTIFY = 0x000F;
    static final short SMB2_QUERY_INFO = 0x0010;
    static final short SMB2_SET_INFO = 0x0011;
    static final short SMB2_OPLOCK_BREAK = 0x0012;

    static final int SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001;
    static final int SMB2_FLAGS_ASYNC_COMMAND = 0x00000002;
    static final int SMB2_FLAGS_RELATED_OPERATIONS = 0x00000004;
    static final int SMB2_FLAGS_SIGNED = 0x00000008;
    static final int SMB2_FLAGS_PRIORITY_MASK = 0x00000070;
    static final int SMB2_FLAGS_DFS_OPERATIONS = 0x10000000;
    static final int SMB2_FLAGS_REPLAY_OPERATION = 0x20000000;

    /*
     * Some fields specify the offset from the beginning of the header. This
     * field should be used for calculating that. This would likely be zero
     * but an implemantation that encorporates the transport header(for
     * efficiency) might use a different initial bufferIndex. For example,
     * to eliminate copying data when writing NbtSession data one might
     * manage that 4 byte header specifically and therefore the initial
     * bufferIndex, and thus headerStart, would be 4).(NOTE: If one where
     * looking for a way to improve perfomance this is precisly what you
     * would want to do as the jcifs.netbios.SocketXxxputStream classes
     * arraycopy all data read or written into a new buffer shifted over 4!)
     */

    short command, flags;
    int headerStart, length, batchLevel, errorCode, flags2, tid, pid, uid, mid, wordCount, byteCount;
    boolean useUnicode, received, extendedSecurity;
    long responseTimeout = 1;
    int signSeq;
    boolean verifyFailed;
    String path;
    SigningDigest digest = null;
    ServerMessageBlock2 response;

    private Configuration config;


    ServerMessageBlock2 ( Configuration config ) {
        this.config = config;
        this.flags = (byte) ( SmbConstants.FLAGS_PATH_NAMES_CASELESS | SmbConstants.FLAGS_PATH_NAMES_CANONICALIZED );
        this.pid = config.getPid();
        this.batchLevel = 0;
    }


    /**
     * @return the config
     */
    protected Configuration getConfig () {
        return this.config;
    }


    void reset () {
        this.flags = (byte) ( SmbConstants.FLAGS_PATH_NAMES_CASELESS | SmbConstants.FLAGS_PATH_NAMES_CANONICALIZED );
        this.flags2 = 0;
        this.errorCode = 0;
        this.received = false;
        this.digest = null;
    }


    int writeString ( String str, byte[] dst, int dstIndex ) {
        return writeString(str, dst, dstIndex, this.useUnicode);
    }


    int writeString ( String str, byte[] dst, int dstIndex, boolean unicode ) {
        int start = dstIndex;
        if ( unicode ) {
            // Unicode requires word alignment
            if ( ( ( dstIndex - this.headerStart ) % 2 ) != 0 ) {
                dst[ dstIndex++ ] = (byte) '\0';
            }
            System.arraycopy(Strings.getUNIBytes(str), 0, dst, dstIndex, str.length() * 2);
            dstIndex += str.length() * 2;
            dst[ dstIndex++ ] = (byte) '\0';
            dst[ dstIndex++ ] = (byte) '\0';
        }
        else {
            byte[] b = Strings.getOEMBytes(str, this.getConfig());
            System.arraycopy(b, 0, dst, dstIndex, b.length);
            dstIndex += b.length;
            dst[ dstIndex++ ] = (byte) '\0';
        }
        return dstIndex - start;
    }


    String readString ( byte[] src, int srcIndex ) {
        return readString(src, srcIndex, 256, this.useUnicode);
    }


    String readString ( byte[] src, int srcIndex, int maxLen, boolean unicode ) {
        if ( unicode ) {
            // Unicode requires word alignment
            if ( ( ( srcIndex - this.headerStart ) % 2 ) != 0 ) {
                srcIndex++;
            }
            return Strings.fromUNIBytes(src, srcIndex, Strings.findUNITermination(src, srcIndex, maxLen));
        }

        return Strings.fromOEMBytes(src, srcIndex, Strings.findTermination(src, srcIndex, maxLen), getConfig());
    }


    String readString ( byte[] src, int srcIndex, int srcEnd, int maxLen, boolean unicode ) {
        if ( unicode ) {
            // Unicode requires word alignment
            if ( ( ( srcIndex - this.headerStart ) % 2 ) != 0 ) {
                srcIndex++;
            }
            return Strings.fromUNIBytes(src, srcIndex, Strings.findUNITermination(src, srcIndex, maxLen));
        }

        return Strings.fromOEMBytes(src, srcIndex, Strings.findTermination(src, srcIndex, maxLen), getConfig());
    }


    int stringWireLength ( String str, int offset ) {
        int len = str.length() + 1;
        if ( this.useUnicode ) {
            len = str.length() * 2 + 2;
            len = ( offset % 2 ) != 0 ? len + 1 : len;
        }
        return len;
    }


    int readStringLength ( byte[] src, int srcIndex, int max ) {
        int len = 0;
        while ( src[ srcIndex + len ] != (byte) 0x00 ) {
            if ( len++ > max ) {
                throw new RuntimeCIFSException("zero termination not found: " + this);
            }
        }
        return len;
    }


    int encode ( byte[] dst, int dstIndex ) {
        int start = this.headerStart = dstIndex;

        dstIndex += writeHeaderWireFormat(dst, dstIndex);
        this.wordCount = writeParameterWordsWireFormat(dst, dstIndex + 1);
        dst[ dstIndex++ ] = (byte) ( ( this.wordCount / 2 ) & 0xFF );
        dstIndex += this.wordCount;
        this.wordCount /= 2;
        this.byteCount = writeBytesWireFormat(dst, dstIndex + 2);
        dst[ dstIndex++ ] = (byte) ( this.byteCount & 0xFF );
        dst[ dstIndex++ ] = (byte) ( ( this.byteCount >> 8 ) & 0xFF );
        dstIndex += this.byteCount;

        this.length = dstIndex - start;

        // if ( this.digest != null ) {
        // this.digest.sign(dst, this.headerStart, this.length, this, this.response);
        // }

        return this.length;
    }


    int decode ( byte[] buffer, int bufferIndex ) {
        int start = this.headerStart = bufferIndex;

        bufferIndex += readHeaderWireFormat(buffer, bufferIndex);

        this.wordCount = buffer[ bufferIndex++ ];
        if ( this.wordCount != 0 ) {
            int n;
            if ( ( n = readParameterWordsWireFormat(buffer, bufferIndex) ) != this.wordCount * 2 ) {
                if ( log.isTraceEnabled() ) {
                    log.trace("wordCount * 2=" + ( this.wordCount * 2 ) + " but readParameterWordsWireFormat returned " + n);
                }
            }
            bufferIndex += this.wordCount * 2;
        }

        this.byteCount = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;

        if ( this.byteCount != 0 ) {
            int n;
            if ( ( n = readBytesWireFormat(buffer, bufferIndex) ) != this.byteCount ) {
                if ( log.isTraceEnabled() ) {
                    log.trace("byteCount=" + this.byteCount + " but readBytesWireFormat returned " + n);
                }
            }
            // Don't think we can rely on n being correct here. Must use byteCount.
            // Last paragraph of section 3.13.3 eludes to this.

            bufferIndex += this.byteCount;
        }

        this.length = bufferIndex - start;
        return this.length;
    }


    int writeHeaderWireFormat ( byte[] dst, int dstIndex ) {
        System.arraycopy(SMBUtil.SMB_HEADER, 0, dst, dstIndex, SMBUtil.SMB_HEADER.length);
        // dst[ dstIndex + SmbConstants.CMD_OFFSET ] = this.command;
        // dst[ dstIndex + SmbConstants.FLAGS_OFFSET ] = this.flags;
        SMBUtil.writeInt2(this.flags2, dst, dstIndex + SmbConstants.FLAGS_OFFSET + 1);
        dstIndex += SmbConstants.TID_OFFSET;
        SMBUtil.writeInt2(this.tid, dst, dstIndex);
        SMBUtil.writeInt2(this.pid, dst, dstIndex + 2);
        SMBUtil.writeInt2(this.uid, dst, dstIndex + 4);
        SMBUtil.writeInt2(this.mid, dst, dstIndex + 6);
        return SmbConstants.HEADER_LENGTH;
    }


    int readHeaderWireFormat ( byte[] buffer, int bufferIndex ) {
        this.command = buffer[ bufferIndex + SmbConstants.CMD_OFFSET ];
        this.errorCode = SMBUtil.readInt4(buffer, bufferIndex + SmbConstants.ERROR_CODE_OFFSET);
        this.flags = buffer[ bufferIndex + SmbConstants.FLAGS_OFFSET ];
        this.flags2 = SMBUtil.readInt2(buffer, bufferIndex + SmbConstants.FLAGS_OFFSET + 1);
        this.tid = SMBUtil.readInt2(buffer, bufferIndex + SmbConstants.TID_OFFSET);
        this.pid = SMBUtil.readInt2(buffer, bufferIndex + SmbConstants.TID_OFFSET + 2);
        this.uid = SMBUtil.readInt2(buffer, bufferIndex + SmbConstants.TID_OFFSET + 4);
        this.mid = SMBUtil.readInt2(buffer, bufferIndex + SmbConstants.TID_OFFSET + 6);
        return SmbConstants.HEADER_LENGTH;
    }


    boolean isResponse () {
        return ( this.flags & SmbConstants.FLAGS_RESPONSE ) == SmbConstants.FLAGS_RESPONSE;
    }


    /*
     * For this packet deconstruction technique to work for
     * other networking protocols the InputStream may need
     * to be passed to the readXxxWireFormat methods. This is
     * actually purer. However, in the case of smb we know the
     * wordCount and byteCount. And since every subclass of
     * ServerMessageBlock would have to perform the same read
     * operation on the input stream, we might as will pull that
     * common functionality into the superclass and read wordCount
     * and byteCount worth of data.
     * 
     * We will still use the readXxxWireFormat return values to
     * indicate how many bytes(note: readParameterWordsWireFormat
     * returns bytes read and not the number of words(but the
     * wordCount member DOES store the number of words)) we
     * actually read. Incedentally this is important to the
     * AndXServerMessageBlock class that needs to potentially
     * read in another smb's parameter words and bytes based on
     * information in it's andxCommand, andxOffset, ...etc.
     */

    abstract int writeParameterWordsWireFormat ( byte[] dst, int dstIndex );


    abstract int writeBytesWireFormat ( byte[] dst, int dstIndex );


    abstract int readParameterWordsWireFormat ( byte[] buffer, int bufferIndex );


    abstract int readBytesWireFormat ( byte[] buffer, int bufferIndex );


    @Override
    public int hashCode () {
        return this.mid;
    }


    @Override
    public boolean equals ( Object obj ) {
        return obj instanceof ServerMessageBlock2 && ( (ServerMessageBlock2) obj ).mid == this.mid;
    }


    @Override
    public String toString () {
        String c;
        switch ( this.command ) {

        case SMB2_NEGOTIATE:
            c = "SMB2_NEGOTIATE";
            break;
        case SMB2_SESSION_SETUP:
            c = "SMB2_SESSION_SETUP";
            break;
        case SMB2_LOGOFF:
            c = "SMB2_LOGOFF";
            break;
        case SMB2_TREE_CONNECT:
            c = "SMB2_TREE_CONNECT";
            break;
        case SMB2_TREE_DISCONNECT:
            c = "SMB2_TREE_DISCONNECT";
            break;
        case SMB2_CREATE:
            c = "SMB2_CREATE";
            break;
        case SMB2_CLOSE:
            c = "SMB2_CLOSE";
            break;
        case SMB2_FLUSH:
            c = "SMB2_FLUSH";
            break;
        case SMB2_READ:
            c = "SMB2_READ";
            break;
        case SMB2_WRITE:
            c = "SMB2_WRITE";
            break;
        case SMB2_LOCK:
            c = "SMB2_LOCK";
            break;
        case SMB2_IOCTL:
            c = "SMB2_IOCTL";
            break;
        case SMB2_CANCEL:
            c = "SMB2_CANCEL";
            break;
        case SMB2_ECHO:
            c = "SMB2_ECHO";
            break;
        case SMB2_QUERY_DIRECTORY:
            c = "SMB2_QUERY_DIRECTORY";
            break;
        case SMB2_CHANGE_NOTIFY:
            c = "SMB2_CHANGE_NOTIFY";
            break;
        case SMB2_QUERY_INFO:
            c = "SMB2_QUERY_INFO";
            break;
        case SMB2_SET_INFO:
            c = "SMB2_SET_INFO";
            break;
        case SMB2_OPLOCK_BREAK:
            c = "SMB2_OPLOCK_BREAK";
            break;
        default:
            c = "UNKNOWN";
        }
        String str = this.errorCode == 0 ? "0" : SmbException.getMessageByCode(this.errorCode);
        return new String(
            "command=" + c + ",received=" + this.received + ",errorCode=" + str + ",flags=0x" + Hexdump.toHexString(this.flags & 0xFF, 4)
                    + ",flags2=0x" + Hexdump.toHexString(this.flags2, 4) + ",signSeq=" + this.signSeq + ",tid=" + this.tid + ",pid=" + this.pid
                    + ",uid=" + this.uid + ",mid=" + this.mid + ",wordCount=" + this.wordCount + ",byteCount=" + this.byteCount);
    }
}
