/*
 * © 2017 AgNO3 Gmbh & Co. KG
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


import jcifs.Configuration;
import jcifs.internal.CommonServerMessageBlock;
import jcifs.internal.CommonServerMessageBlockResponse;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.SMBSigningDigest;
import jcifs.internal.util.SMBUtil;
import jcifs.smb.SmbException;
import jcifs.util.Hexdump;


/**
 * 
 * @author mbechler
 *
 */
public abstract class ServerMessageBlock2 implements CommonServerMessageBlock {

    /*
     * These are all the smbs supported by this library. This includes requests
     * and well as their responses for each type however the actual implementations
     * of the readXxxWireFormat and writeXxxWireFormat methods may not be in
     * place. For example at the time of this writing the readXxxWireFormat
     * for requests and the writeXxxWireFormat for responses are not implemented
     * and simply return 0. These would need to be completed for a server
     * implementation.
     */

    protected static final short SMB2_NEGOTIATE = 0x00;
    protected static final short SMB2_SESSION_SETUP = 0x01;
    protected static final short SMB2_LOGOFF = 0x02;
    protected static final short SMB2_TREE_CONNECT = 0x0003;
    protected static final short SMB2_TREE_DISCONNECT = 0x0004;
    protected static final short SMB2_CREATE = 0x0005;
    protected static final short SMB2_CLOSE = 0x0006;
    protected static final short SMB2_FLUSH = 0x0007;
    protected static final short SMB2_READ = 0x0008;
    protected static final short SMB2_WRITE = 0x0009;
    protected static final short SMB2_LOCK = 0x000A;
    protected static final short SMB2_IOCTL = 0x000B;
    protected static final short SMB2_CANCEL = 0x000C;
    protected static final short SMB2_ECHO = 0x000D;
    protected static final short SMB2_QUERY_DIRECTORY = 0x000E;
    protected static final short SMB2_CHANGE_NOTIFY = 0x000F;
    protected static final short SMB2_QUERY_INFO = 0x0010;
    protected static final short SMB2_SET_INFO = 0x0011;
    protected static final short SMB2_OPLOCK_BREAK = 0x0012;

    /**
     * 
     */
    public static final int SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001;
    /**
     * 
     */
    public static final int SMB2_FLAGS_ASYNC_COMMAND = 0x00000002;
    /**
     * 
     */
    public static final int SMB2_FLAGS_RELATED_OPERATIONS = 0x00000004;
    /**
     * 
     */
    public static final int SMB2_FLAGS_SIGNED = 0x00000008;
    /**
     * 
     */
    public static final int SMB2_FLAGS_PRIORITY_MASK = 0x00000070;
    /**
     * 
     */
    public static final int SMB2_FLAGS_DFS_OPERATIONS = 0x10000000;
    /**
     * 
     */
    public static final int SMB2_FLAGS_REPLAY_OPERATION = 0x20000000;

    private int command;
    private int flags;
    private int length, headerStart, wordCount, byteCount;

    private byte[] signature = new byte[16];
    private Smb2SigningDigest digest = null;

    private Configuration config;

    private int creditCharge;
    private int status;
    private int credit;
    private int nextCommand;
    private int readSize;
    private boolean async;
    private int treeId;
    private long mid, asyncId, sessionId;
    private byte errorContextCount;
    private byte[] errorData;

    private boolean retainPayload;
    private byte[] rawPayload;

    private ServerMessageBlock2 next;


    protected ServerMessageBlock2 ( Configuration config ) {
        this.config = config;
    }


    protected ServerMessageBlock2 ( Configuration config, int command ) {
        this.config = config;
        this.command = command;
    }


    /**
     * @return the config
     */
    protected Configuration getConfig () {
        return this.config;
    }


    @Override
    public void reset () {
        this.flags = 0;
        this.digest = null;
        this.sessionId = 0;
        this.treeId = 0;
    }


    /**
     * @return the command
     */
    @Override
    public final int getCommand () {
        return this.command;
    }


    /**
     * @return offset to next compound command
     */
    public final int getNextCommandOffset () {
        return this.nextCommand;
    }


    /**
     * @param readSize
     *            the readSize to set
     */
    public void setReadSize ( int readSize ) {
        this.readSize = readSize;
    }


    /**
     * @return the async
     */
    public boolean isAsync () {
        return this.async;
    }


    /**
     * @param command
     *            the command to set
     */
    @Override
    public final void setCommand ( int command ) {
        this.command = command;
    }


    /**
     * @return the treeId
     */
    public final int getTreeId () {
        return this.treeId;
    }


    /**
     * @param treeId
     *            the treeId to set
     */
    public final void setTreeId ( int treeId ) {
        this.treeId = treeId;
        if ( this.next != null ) {
            this.next.setTreeId(treeId);
        }
    }


    /**
     * @return the asyncId
     */
    public final long getAsyncId () {
        return this.asyncId;
    }


    /**
     * @param asyncId
     *            the asyncId to set
     */
    public final void setAsyncId ( long asyncId ) {
        this.asyncId = asyncId;
    }


    /**
     * @return the credit
     */
    public final int getCredit () {
        return this.credit;
    }


    /**
     * @param credit
     *            the credit to set
     */
    public final void setCredit ( int credit ) {
        this.credit = credit;
    }


    /**
     * @return the creditCharge
     */
    public final int getCreditCharge () {
        return this.creditCharge;
    }


    @Override
    public void retainPayload () {
        this.retainPayload = true;
    }


    @Override
    public boolean isRetainPayload () {
        return this.retainPayload;
    }


    @Override
    public byte[] getRawPayload () {
        return this.rawPayload;
    }


    @Override
    public void setRawPayload ( byte[] rawPayload ) {
        this.rawPayload = rawPayload;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlock#getDigest()
     */
    @Override
    public Smb2SigningDigest getDigest () {
        return this.digest;
    }


    /**
     * 
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlock#setDigest(jcifs.internal.SMBSigningDigest)
     */
    @Override
    public void setDigest ( SMBSigningDigest digest ) {
        this.digest = (Smb2SigningDigest) digest;
        if ( this.next != null ) {
            this.next.setDigest(digest);
        }
    }


    /**
     * @return the status
     */
    public final int getStatus () {
        return this.status;
    }


    /**
     * @return the sessionId
     */
    public long getSessionId () {
        return this.sessionId;
    }


    /**
     * @param sessionId
     *            the sessionId to set
     */
    @Override
    public final void setSessionId ( long sessionId ) {
        this.sessionId = sessionId;
        if ( this.next != null ) {
            this.next.setSessionId(sessionId);
        }
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlock#setExtendedSecurity(boolean)
     */
    @Override
    public void setExtendedSecurity ( boolean extendedSecurity ) {
        // ignore
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlock#setUid(int)
     */
    @Override
    public void setUid ( int uid ) {
        // ignore
    }


    /**
     * @return the flags
     */
    public final int getFlags () {
        return this.flags;
    }


    /**
     * 
     * @param flag
     */
    public final void addFlags ( int flag ) {
        this.flags |= flag;
    }


    /**
     * 
     * @param flag
     */
    public final void clearFlags ( int flag ) {
        this.flags &= ~flag;
    }


    /**
     * @return the mid
     */
    @Override
    public final long getMid () {
        return this.mid;
    }


    /**
     * @param mid
     *            the mid to set
     */
    @Override
    public final void setMid ( long mid ) {
        this.mid = mid;
    }


    /**
     * @param n
     * @return whether chaining was successful
     */
    public boolean chain ( ServerMessageBlock2 n ) {
        if ( this.next != null ) {
            return this.next.chain(n);
        }

        n.addFlags(SMB2_FLAGS_RELATED_OPERATIONS);
        this.next = n;
        return true;
    }


    protected ServerMessageBlock2 getNext () {
        return this.next;
    }


    protected void setNext ( ServerMessageBlock2 n ) {
        this.next = n;
    }


    /**
     * @return the response
     */
    @Override
    public ServerMessageBlock2Response getResponse () {
        return null;
    }


    /**
     * 
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlock#setResponse(jcifs.internal.CommonServerMessageBlockResponse)
     */
    @Override
    public void setResponse ( CommonServerMessageBlockResponse msg ) {

    }


    /**
     * @return the errorData
     */
    public final byte[] getErrorData () {
        return this.errorData;
    }


    /**
     * @return the errorContextCount
     */
    public final byte getErrorContextCount () {
        return this.errorContextCount;
    }


    /**
     * @return the headerStart
     */
    public final int getHeaderStart () {
        return this.headerStart;
    }


    /**
     * @return the length
     */
    public final int getLength () {
        return this.length;
    }


    @Override
    public int encode ( byte[] dst, int dstIndex ) {
        int start = this.headerStart = dstIndex;
        dstIndex += writeHeaderWireFormat(dst, dstIndex);

        this.byteCount = writeBytesWireFormat(dst, dstIndex);
        dstIndex += this.byteCount;
        dstIndex += pad8(dstIndex);

        this.length = dstIndex - start;

        int len = this.length;

        if ( this.next != null ) {
            int nextStart = dstIndex;
            dstIndex += this.next.encode(dst, dstIndex);
            int off = nextStart - start;
            SMBUtil.writeInt4(off, dst, start + 20);
            len += dstIndex - nextStart;
        }

        if ( this.digest != null ) {
            this.digest.sign(dst, this.headerStart, this.length, this, getResponse());
        }

        if ( isRetainPayload() ) {
            this.rawPayload = new byte[len];
            System.arraycopy(dst, start, this.rawPayload, 0, len);
        }

        return len;
    }


    protected static final int size8 ( int size ) {
        return size8(size, 0);
    }


    protected static final int size8 ( int size, int align ) {

        int rem = size % 8 - align;
        if ( rem == 0 ) {
            return size;
        }
        if ( rem < 0 ) {
            rem = 8 + rem;
        }
        return size + 8 - rem;
    }


    /**
     * @param dstIndex
     * @return
     */
    protected final int pad8 ( int dstIndex ) {
        int fromHdr = dstIndex - this.headerStart;
        int rem = fromHdr % 8;
        if ( rem == 0 ) {
            return 0;
        }
        return 8 - rem;
    }


    @Override
    public int decode ( byte[] buffer, int bufferIndex ) throws SMBProtocolDecodingException {
        return decode(buffer, bufferIndex, false);
    }


    /**
     * @param buffer
     * @param bufferIndex
     * @param compound
     * @return decoded length
     * @throws SMBProtocolDecodingException
     */
    public int decode ( byte[] buffer, int bufferIndex, boolean compound ) throws SMBProtocolDecodingException {
        int start = this.headerStart = bufferIndex;
        bufferIndex += readHeaderWireFormat(buffer, bufferIndex);
        if ( isErrorResponseStatus() ) {
            bufferIndex += readErrorResponse(buffer, bufferIndex);
        }
        else {
            bufferIndex += readBytesWireFormat(buffer, bufferIndex);
        }

        this.length = bufferIndex - start;
        int len = this.length;

        if ( this.nextCommand != 0 ) {
            // padding becomes part of signature if this is _PART_ of a compound chain
            len += pad8(bufferIndex);
        }
        else if ( compound && this.nextCommand == 0 && this.readSize > 0 ) {
            // TODO: only apply this for actual compound chains, or is this correct for single responses, too?
            // 3.2.5.1.9 Handling Compounded Responses
            // The final response in the compounded response chain will have NextCommand equal to 0,
            // and it MUST be processed as an individual message of a size equal to the number of bytes
            // remaining in this receive.
            int rem = this.readSize - this.length;
            len += rem;
        }

        haveResponse(buffer, start, len);

        if ( this.nextCommand != 0 && this.next != null ) {
            if ( this.nextCommand % 8 != 0 ) {
                throw new SMBProtocolDecodingException("Chained command is not aligned");
            }
        }
        return len;
    }


    protected boolean isErrorResponseStatus () {
        return getStatus() != 0;
    }


    /**
     * @param buffer
     * @param start
     * @param len
     * @throws SMBProtocolDecodingException
     */
    protected void haveResponse ( byte[] buffer, int start, int len ) throws SMBProtocolDecodingException {}


    /**
     * @param buffer
     * @param bufferIndex
     * @return
     * @throws Smb2ProtocolDecodingException
     */
    protected int readErrorResponse ( byte[] buffer, int bufferIndex ) throws SMBProtocolDecodingException {
        int start = bufferIndex;
        int structureSize = SMBUtil.readInt2(buffer, bufferIndex);
        if ( structureSize != 9 ) {
            throw new SMBProtocolDecodingException("Error structureSize should be 9");
        }
        this.errorContextCount = buffer[ bufferIndex + 2 ];
        bufferIndex += 4;

        int bc = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        if ( bc > 0 ) {
            this.errorData = new byte[bc];
            System.arraycopy(buffer, bufferIndex, this.errorData, 0, bc);
            bufferIndex += bc;
        }
        return bufferIndex - start;
    }


    protected int writeHeaderWireFormat ( byte[] dst, int dstIndex ) {
        System.arraycopy(SMBUtil.SMB2_HEADER, 0, dst, dstIndex, SMBUtil.SMB2_HEADER.length);

        SMBUtil.writeInt2(this.creditCharge, dst, dstIndex + 6);
        SMBUtil.writeInt2(this.command, dst, dstIndex + 12);
        SMBUtil.writeInt2(this.credit, dst, dstIndex + 14);
        SMBUtil.writeInt4(this.flags, dst, dstIndex + 16);
        SMBUtil.writeInt4(this.nextCommand, dst, dstIndex + 20);
        SMBUtil.writeInt8(this.mid, dst, dstIndex + 24);

        if ( this.async ) {
            SMBUtil.writeInt8(this.asyncId, dst, dstIndex + 32);
            SMBUtil.writeInt8(this.sessionId, dst, dstIndex + 40);
        }
        else {
            // 4 reserved
            SMBUtil.writeInt4(this.treeId, dst, dstIndex + 36);
            SMBUtil.writeInt8(this.sessionId, dst, dstIndex + 40);
            // + signature
        }

        return Smb2Constants.SMB2_HEADER_LENGTH;
    }


    protected int readHeaderWireFormat ( byte[] buffer, int bufferIndex ) {
        // these are common between SYNC/ASYNC
        SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        SMBUtil.readInt2(buffer, bufferIndex);
        this.creditCharge = SMBUtil.readInt2(buffer, bufferIndex + 2);
        bufferIndex += 4;
        this.status = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.command = SMBUtil.readInt2(buffer, bufferIndex);
        this.credit = SMBUtil.readInt2(buffer, bufferIndex + 2);
        bufferIndex += 4;

        this.flags = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.nextCommand = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.mid = SMBUtil.readInt8(buffer, bufferIndex);
        bufferIndex += 8;

        if ( ( this.flags & SMB2_FLAGS_ASYNC_COMMAND ) == SMB2_FLAGS_ASYNC_COMMAND ) {
            // async
            this.async = true;
            this.asyncId = SMBUtil.readInt8(buffer, bufferIndex);
            bufferIndex += 8;
            this.sessionId = SMBUtil.readInt8(buffer, bufferIndex);
            bufferIndex += 8;
            System.arraycopy(buffer, bufferIndex, this.signature, 0, 16);
            bufferIndex += 16;
        }
        else {
            // sync
            this.async = false;
            bufferIndex += 4; // reserved
            this.treeId = SMBUtil.readInt4(buffer, bufferIndex);
            bufferIndex += 4;
            this.sessionId = SMBUtil.readInt8(buffer, bufferIndex);
            bufferIndex += 8;
            System.arraycopy(buffer, bufferIndex, this.signature, 0, 16);
            bufferIndex += 16;
        }

        return Smb2Constants.SMB2_HEADER_LENGTH;
    }


    boolean isResponse () {
        return ( this.flags & SMB2_FLAGS_SERVER_TO_REDIR ) == SMB2_FLAGS_SERVER_TO_REDIR;
    }


    protected abstract int writeBytesWireFormat ( byte[] dst, int dstIndex );


    protected abstract int readBytesWireFormat ( byte[] buffer, int bufferIndex ) throws SMBProtocolDecodingException;


    @Override
    public int hashCode () {
        return (int) this.mid;
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
        String str = this.status == 0 ? "0" : SmbException.getMessageByCode(this.status);
        return new String(
            "command=" + c + ",status=" + str + ",flags=0x" + Hexdump.toHexString(this.flags, 4) + ",mid=" + this.mid + ",wordCount=" + this.wordCount
                    + ",byteCount=" + this.byteCount);
    }

}
