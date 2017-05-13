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

package jcifs.internal.smb1;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.Configuration;
import jcifs.RuntimeCIFSException;
import jcifs.SmbConstants;
import jcifs.internal.util.SMBUtil;
import jcifs.internal.util.SigningDigest;
import jcifs.smb.SmbException;
import jcifs.util.Hexdump;
import jcifs.util.Strings;
import jcifs.util.transport.Request;
import jcifs.util.transport.Response;


/**
 * 
 * 
 */
public abstract class ServerMessageBlock extends Response implements Request {

    private static final Logger log = LoggerFactory.getLogger(ServerMessageBlock.class);

    /*
     * These are all the smbs supported by this library. This includes requests
     * and well as their responses for each type however the actuall implementations
     * of the readXxxWireFormat and writeXxxWireFormat methods may not be in
     * place. For example at the time of this writing the readXxxWireFormat
     * for requests and the writeXxxWireFormat for responses are not implemented
     * and simply return 0. These would need to be completed for a server
     * implementation.
     */

    /**
     * 
     */
    public static final byte SMB_COM_CREATE_DIRECTORY = (byte) 0x00;

    /**
     * 
     */
    public static final byte SMB_COM_DELETE_DIRECTORY = (byte) 0x01;

    /**
     * 
     */
    public static final byte SMB_COM_CLOSE = (byte) 0x04;

    /**
     * 
     */
    public static final byte SMB_COM_DELETE = (byte) 0x06;

    /**
     * 
     */
    public static final byte SMB_COM_RENAME = (byte) 0x07;

    /**
     * 
     */
    public static final byte SMB_COM_QUERY_INFORMATION = (byte) 0x08;

    /**
     * 
     */
    public static final byte SMB_COM_SET_INFORMATION = (byte) 0x09;

    /**
     * 
     */
    public static final byte SMB_COM_WRITE = (byte) 0x0B;

    /**
     * 
     */
    public static final byte SMB_COM_CHECK_DIRECTORY = (byte) 0x10;

    /**
     * 
     */
    public static final byte SMB_COM_TRANSACTION = (byte) 0x25;

    /**
     * 
     */
    public static final byte SMB_COM_TRANSACTION_SECONDARY = (byte) 0x26;

    /**
     * 
     */
    public static final byte SMB_COM_MOVE = (byte) 0x2A;

    /**
     * 
     */
    public static final byte SMB_COM_ECHO = (byte) 0x2B;

    /**
     * 
     */
    public static final byte SMB_COM_OPEN_ANDX = (byte) 0x2D;

    /**
     * 
     */
    public static final byte SMB_COM_READ_ANDX = (byte) 0x2E;

    /**
     * 
     */
    public static final byte SMB_COM_WRITE_ANDX = (byte) 0x2F;

    /**
     * 
     */
    public static final byte SMB_COM_TRANSACTION2 = (byte) 0x32;

    /**
     * 
     */
    public static final byte SMB_COM_FIND_CLOSE2 = (byte) 0x34;

    /**
     * 
     */
    public static final byte SMB_COM_TREE_DISCONNECT = (byte) 0x71;

    /**
     * 
     */
    public static final byte SMB_COM_NEGOTIATE = (byte) 0x72;

    /**
     * 
     */
    public static final byte SMB_COM_SESSION_SETUP_ANDX = (byte) 0x73;

    /**
     * 
     */
    public static final byte SMB_COM_LOGOFF_ANDX = (byte) 0x74;

    /**
     * 
     */
    public static final byte SMB_COM_TREE_CONNECT_ANDX = (byte) 0x75;

    /**
     * 
     */
    public static final byte SMB_COM_NT_TRANSACT = (byte) 0xA0;

    /**
     * 
     */
    public static final byte SMB_COM_NT_TRANSACT_SECONDARY = (byte) 0xA1;

    /**
     * 
     */
    public static final byte SMB_COM_NT_CREATE_ANDX = (byte) 0xA2;

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

    private byte command, flags;
    protected int headerStart, length, batchLevel, errorCode, flags2, tid, pid, uid, mid, wordCount, byteCount;
    private boolean useUnicode, forceUnicode, received, extendedSecurity;
    private int signSeq;
    private boolean verifyFailed;
    protected String path;
    protected SigningDigest digest = null;
    private ServerMessageBlock response;

    private Configuration config;


    protected ServerMessageBlock ( Configuration config ) {
        this(config, (byte) 0);
    }


    protected ServerMessageBlock ( Configuration config, byte command ) {
        this(config, command, null);
    }


    protected ServerMessageBlock ( Configuration config, byte command, String path ) {
        this.config = config;
        this.command = command;
        this.path = path;
        this.flags = (byte) ( SmbConstants.FLAGS_PATH_NAMES_CASELESS | SmbConstants.FLAGS_PATH_NAMES_CANONICALIZED );
        this.pid = config.getPid();
        this.batchLevel = 0;
    }


    /**
     * @return the command
     */
    public final byte getCommand () {
        return this.command;
    }


    /**
     * @param command
     *            the command to set
     */
    public final void setCommand ( byte command ) {
        this.command = command;
    }


    /**
     * @return the byteCount
     */
    public final int getByteCount () {
        return this.byteCount;
    }


    /**
     * @return the length
     */
    public final int getLength () {
        return this.length;
    }


    /**
     * @return the forceUnicode
     */
    public boolean isForceUnicode () {
        return this.forceUnicode;
    }


    /**
     * @return the flags
     */
    public final byte getFlags () {
        return this.flags;
    }


    /**
     * @param flags
     *            the flags to set
     */
    public final void setFlags ( byte flags ) {
        this.flags = flags;
    }


    /**
     * @return the flags2
     */
    public final int getFlags2 () {
        return this.flags2;
    }


    /**
     * @param fl
     *            the flags2 to set
     */
    public final void setFlags2 ( int fl ) {
        this.flags2 = fl;
    }


    /**
     * @param fl
     */
    public final void addFlags2 ( int fl ) {
        this.flags2 |= fl;
    }


    /**
     * 
     * @param fl
     */
    public final void remFlags2 ( int fl ) {
        this.flags2 &= ~fl;
    }


    /**
     * @return the errorCode
     */
    public final int getErrorCode () {
        return this.errorCode;
    }


    /**
     * @param errorCode
     *            the errorCode to set
     */
    public final void setErrorCode ( int errorCode ) {
        this.errorCode = errorCode;
    }


    /**
     * @return the path
     */
    public final String getPath () {
        return this.path;
    }


    /**
     * @param path
     *            the path to set
     */
    public final void setPath ( String path ) {
        this.path = path;
    }


    /**
     * @return the digest
     */
    public final SigningDigest getDigest () {
        return this.digest;
    }


    /**
     * @param digest
     *            the digest to set
     */
    public final void setDigest ( SigningDigest digest ) {
        this.digest = digest;
    }


    /**
     * @return the extendedSecurity
     */
    public boolean isExtendedSecurity () {
        return this.extendedSecurity;
    }


    /**
     * @param extendedSecurity
     *            the extendedSecurity to set
     */
    public void setExtendedSecurity ( boolean extendedSecurity ) {
        this.extendedSecurity = extendedSecurity;
    }


    /**
     * @return the useUnicode
     */
    public final boolean isUseUnicode () {
        return this.useUnicode;
    }


    /**
     * @param useUnicode
     *            the useUnicode to set
     */
    public final void setUseUnicode ( boolean useUnicode ) {
        this.useUnicode = useUnicode;
    }


    /**
     * @return the received
     */
    public final boolean isReceived () {
        return this.received;
    }


    /**
     * @param received
     *            the received to set
     */
    public final void setReceived ( boolean received ) {
        this.received = received;
    }


    /**
     * @return the response
     */
    public final ServerMessageBlock getResponse () {
        return this.response;
    }


    /**
     * @param response
     *            the response to set
     */
    public final void setResponse ( ServerMessageBlock response ) {
        this.response = response;
    }


    /**
     * @return the mid
     */
    public final int getMid () {
        return this.mid;
    }


    /**
     * @param mid
     *            the mid to set
     */
    public final void setMid ( int mid ) {
        this.mid = mid;
    }


    /**
     * @return the tid
     */
    public final int getTid () {
        return this.tid;
    }


    /**
     * @param tid
     *            the tid to set
     */
    public final void setTid ( int tid ) {
        this.tid = tid;
    }


    /**
     * @return the pid
     */
    public final int getPid () {
        return this.pid;
    }


    /**
     * @param pid
     *            the pid to set
     */
    public final void setPid ( int pid ) {
        this.pid = pid;
    }


    /**
     * @return the uid
     */
    public final int getUid () {
        return this.uid;
    }


    /**
     * @param uid
     *            the uid to set
     */
    public final void setUid ( int uid ) {
        this.uid = uid;
    }


    /**
     * @return the signSeq
     */
    public int getSignSeq () {
        return this.signSeq;
    }


    /**
     * @param signSeq
     *            the signSeq to set
     */
    public final void setSignSeq ( int signSeq ) {
        this.signSeq = signSeq;
    }


    /**
     * @return the verifyFailed
     */
    public boolean isVerifyFailed () {
        return this.verifyFailed;
    }


    /**
     * @param verifyFailed
     *            the verifyFailed to set
     * @return verification status
     */
    public boolean setVerifyFailed ( boolean verifyFailed ) {
        return this.verifyFailed = verifyFailed;
    }


    /**
     * @return the config
     */
    protected final Configuration getConfig () {
        return this.config;
    }


    /**
     * 
     */
    public void reset () {
        this.flags = (byte) ( SmbConstants.FLAGS_PATH_NAMES_CASELESS | SmbConstants.FLAGS_PATH_NAMES_CANONICALIZED );
        this.flags2 = 0;
        this.errorCode = 0;
        this.received = false;
        this.digest = null;
    }


    protected int writeString ( String str, byte[] dst, int dstIndex ) {
        return writeString(str, dst, dstIndex, this.useUnicode);
    }


    protected int writeString ( String str, byte[] dst, int dstIndex, boolean unicode ) {
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


    /**
     * 
     * @param src
     * @param srcIndex
     * @return read string
     */
    public String readString ( byte[] src, int srcIndex ) {
        return readString(src, srcIndex, 255, this.useUnicode);
    }


    /**
     * 
     * @param src
     * @param srcIndex
     * @param maxLen
     * @param unicode
     * @return read string
     */
    public String readString ( byte[] src, int srcIndex, int maxLen, boolean unicode ) {
        if ( unicode ) {
            // Unicode requires word alignment
            if ( ( ( srcIndex - this.headerStart ) % 2 ) != 0 ) {
                srcIndex++;
            }
            return Strings.fromUNIBytes(src, srcIndex, Strings.findUNITermination(src, srcIndex, maxLen));
        }

        return Strings.fromOEMBytes(src, srcIndex, Strings.findTermination(src, srcIndex, maxLen), getConfig());
    }


    /**
     * 
     * @param src
     * @param srcIndex
     * @param srcEnd
     * @param maxLen
     * @param unicode
     * @return read string
     */
    public String readString ( byte[] src, int srcIndex, int srcEnd, int maxLen, boolean unicode ) {
        if ( unicode ) {
            // Unicode requires word alignment
            if ( ( ( srcIndex - this.headerStart ) % 2 ) != 0 ) {
                srcIndex++;
            }
            return Strings.fromUNIBytes(src, srcIndex, Strings.findUNITermination(src, srcIndex, maxLen));
        }

        return Strings.fromOEMBytes(src, srcIndex, Strings.findTermination(src, srcIndex, maxLen), getConfig());
    }


    /**
     * 
     * @param str
     * @param offset
     * @return string length
     */
    public int stringWireLength ( String str, int offset ) {
        int len = str.length() + 1;
        if ( this.useUnicode ) {
            len = str.length() * 2 + 2;
            len = ( offset % 2 ) != 0 ? len + 1 : len;
        }
        return len;
    }


    protected int readStringLength ( byte[] src, int srcIndex, int max ) {
        int len = 0;
        while ( src[ srcIndex + len ] != (byte) 0x00 ) {
            if ( len++ > max ) {
                throw new RuntimeCIFSException("zero termination not found: " + this);
            }
        }
        return len;
    }


    /**
     * Encode message from the data
     * 
     * @param dst
     * @param dstIndex
     * @return message length
     */
    public int encode ( byte[] dst, int dstIndex ) {
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

        if ( this.digest != null ) {
            this.digest.sign(dst, this.headerStart, this.length, this, this.response);
        }

        return this.length;
    }


    /**
     * Decode message data from the given byte array
     * 
     * @param buffer
     * @param bufferIndex
     * @return message length
     */
    public int decode ( byte[] buffer, int bufferIndex ) {
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


    protected int writeHeaderWireFormat ( byte[] dst, int dstIndex ) {
        System.arraycopy(SMBUtil.SMB_HEADER, 0, dst, dstIndex, SMBUtil.SMB_HEADER.length);
        dst[ dstIndex + SmbConstants.CMD_OFFSET ] = this.command;
        dst[ dstIndex + SmbConstants.FLAGS_OFFSET ] = this.flags;
        SMBUtil.writeInt2(this.flags2, dst, dstIndex + SmbConstants.FLAGS_OFFSET + 1);
        dstIndex += SmbConstants.TID_OFFSET;
        SMBUtil.writeInt2(this.tid, dst, dstIndex);
        SMBUtil.writeInt2(this.pid, dst, dstIndex + 2);
        SMBUtil.writeInt2(this.uid, dst, dstIndex + 4);
        SMBUtil.writeInt2(this.mid, dst, dstIndex + 6);
        return SmbConstants.HEADER_LENGTH;
    }


    protected int readHeaderWireFormat ( byte[] buffer, int bufferIndex ) {
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


    protected boolean isResponse () {
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

    protected abstract int writeParameterWordsWireFormat ( byte[] dst, int dstIndex );


    protected abstract int writeBytesWireFormat ( byte[] dst, int dstIndex );


    protected abstract int readParameterWordsWireFormat ( byte[] buffer, int bufferIndex );


    protected abstract int readBytesWireFormat ( byte[] buffer, int bufferIndex );


    @Override
    public int hashCode () {
        return this.mid;
    }


    @Override
    public boolean equals ( Object obj ) {
        return obj instanceof ServerMessageBlock && ( (ServerMessageBlock) obj ).mid == this.mid;
    }


    @Override
    public String toString () {
        String c;
        switch ( this.command ) {
        case SMB_COM_NEGOTIATE:
            c = "SMB_COM_NEGOTIATE";
            break;
        case SMB_COM_SESSION_SETUP_ANDX:
            c = "SMB_COM_SESSION_SETUP_ANDX";
            break;
        case SMB_COM_TREE_CONNECT_ANDX:
            c = "SMB_COM_TREE_CONNECT_ANDX";
            break;
        case SMB_COM_QUERY_INFORMATION:
            c = "SMB_COM_QUERY_INFORMATION";
            break;
        case SMB_COM_CHECK_DIRECTORY:
            c = "SMB_COM_CHECK_DIRECTORY";
            break;
        case SMB_COM_TRANSACTION:
            c = "SMB_COM_TRANSACTION";
            break;
        case SMB_COM_TRANSACTION2:
            c = "SMB_COM_TRANSACTION2";
            break;
        case SMB_COM_TRANSACTION_SECONDARY:
            c = "SMB_COM_TRANSACTION_SECONDARY";
            break;
        case SMB_COM_FIND_CLOSE2:
            c = "SMB_COM_FIND_CLOSE2";
            break;
        case SMB_COM_TREE_DISCONNECT:
            c = "SMB_COM_TREE_DISCONNECT";
            break;
        case SMB_COM_LOGOFF_ANDX:
            c = "SMB_COM_LOGOFF_ANDX";
            break;
        case SMB_COM_ECHO:
            c = "SMB_COM_ECHO";
            break;
        case SMB_COM_MOVE:
            c = "SMB_COM_MOVE";
            break;
        case SMB_COM_RENAME:
            c = "SMB_COM_RENAME";
            break;
        case SMB_COM_DELETE:
            c = "SMB_COM_DELETE";
            break;
        case SMB_COM_DELETE_DIRECTORY:
            c = "SMB_COM_DELETE_DIRECTORY";
            break;
        case SMB_COM_NT_CREATE_ANDX:
            c = "SMB_COM_NT_CREATE_ANDX";
            break;
        case SMB_COM_OPEN_ANDX:
            c = "SMB_COM_OPEN_ANDX";
            break;
        case SMB_COM_READ_ANDX:
            c = "SMB_COM_READ_ANDX";
            break;
        case SMB_COM_CLOSE:
            c = "SMB_COM_CLOSE";
            break;
        case SMB_COM_WRITE_ANDX:
            c = "SMB_COM_WRITE_ANDX";
            break;
        case SMB_COM_CREATE_DIRECTORY:
            c = "SMB_COM_CREATE_DIRECTORY";
            break;
        case SMB_COM_NT_TRANSACT:
            c = "SMB_COM_NT_TRANSACT";
            break;
        case SMB_COM_NT_TRANSACT_SECONDARY:
            c = "SMB_COM_NT_TRANSACT_SECONDARY";
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
