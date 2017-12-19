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
package jcifs.internal.smb2.create;


import java.nio.charset.StandardCharsets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.internal.RequestWithPath;
import jcifs.internal.smb2.ServerMessageBlock2Request;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.util.SMBUtil;


/**
 * @author mbechler
 *
 */
public class Smb2CreateRequest extends ServerMessageBlock2Request<Smb2CreateResponse> implements RequestWithPath {

    private static final Logger log = LoggerFactory.getLogger(Smb2CreateRequest.class);

    /**
     * 
     */
    public static final byte SMB2_OPLOCK_LEVEL_NONE = 0x0;
    /**
     * 
     */
    public static final byte SMB2_OPLOCK_LEVEL_II = 0x1;
    /**
     * 
     */
    public static final byte SMB2_OPLOCK_LEVEL_EXCLUSIVE = 0x8;
    /**
     * 
     */
    public static final byte SMB2_OPLOCK_LEVEL_BATCH = 0x9;
    /**
     * 
     */
    public static final byte SMB2_OPLOCK_LEVEL_LEASE = (byte) 0xFF;

    /**
     * 
     */
    public static final int SMB2_IMPERSONATION_LEVEL_ANONYMOUS = 0x0;

    /**
     * 
     */
    public static final int SMB2_IMPERSONATION_LEVEL_IDENTIFICATION = 0x1;

    /**
     * 
     */
    public static final int SMB2_IMPERSONATION_LEVEL_IMPERSONATION = 0x2;

    /**
     * 
     */
    public static final int SMB2_IMPERSONATION_LEVEL_DELEGATE = 0x3;

    /**
     * 
     */
    public static final int FILE_SHARE_READ = 0x1;

    /**
     * 
     */
    public static final int FILE_SHARE_WRITE = 0x2;

    /**
     * 
     */
    public static final int FILE_SHARE_DELETE = 0x4;

    /**
     * 
     */
    public static final int FILE_SUPERSEDE = 0x0;
    /**
     * 
     */
    public static final int FILE_OPEN = 0x1;
    /**
     * 
     */
    public static final int FILE_CREATE = 0x2;
    /**
     * 
     */
    public static final int FILE_OPEN_IF = 0x3;
    /**
     * 
     */
    public static final int FILE_OVERWRITE = 0x4;
    /**
     * 
     */
    public static final int FILE_OVERWRITE_IF = 0x5;

    /**
     * 
     */
    public static final int FILE_DIRECTORY_FILE = 0x1;
    /**
     * 
     */
    public static final int FILE_WRITE_THROUGH = 0x2;
    /**
     * 
     */
    public static final int FILE_SEQUENTIAL_ONLY = 0x4;
    /**
     * 
     */
    public static final int FILE_NO_IMTERMEDIATE_BUFFERING = 0x8;
    /**
     * 
     */
    public static final int FILE_SYNCHRONOUS_IO_ALERT = 0x10;
    /**
     * 
     */
    public static final int FILE_SYNCHRONOUS_IO_NONALERT = 0x20;
    /**
     * 
     */
    public static final int FILE_NON_DIRECTORY_FILE = 0x40;
    /**
     * 
     */
    public static final int FILE_COMPLETE_IF_OPLOCKED = 0x100;
    /**
     * 
     */
    public static final int FILE_NO_EA_KNOWLEDGE = 0x200;
    /**
     * 
     */
    public static final int FILE_OPEN_REMOTE_INSTANCE = 0x400;
    /**
     * 
     */
    public static final int FILE_RANDOM_ACCESS = 0x800;
    /**
     * 
     */
    public static final int FILE_DELETE_ON_CLOSE = 0x1000;
    /**
     * 
     */
    public static final int FILE_OPEN_BY_FILE_ID = 0x2000;
    /**
     * 
     */
    public static final int FILE_OPEN_FOR_BACKUP_INTENT = 0x4000;
    /**
     * 
     */
    public static final int FILE_NO_COMPRESSION = 0x8000;
    /**
     * 
     */
    public static final int FILE_OPEN_REQUIRING_OPLOCK = 0x10000;
    /**
     * 
     */
    public static final int FILE_DISALLOW_EXCLUSIVE = 0x20000;
    /**
     * 
     */
    public static final int FILE_RESERVE_OPFILTER = 0x100000;
    /**
     * 
     */
    public static final int FILE_OPEN_REPARSE_POINT = 0x200000;
    /**
     * 
     */
    public static final int FILE_NOP_RECALL = 0x400000;
    /**
     * 
     */
    public static final int FILE_OPEN_FOR_FREE_SPACE_QUERY = 0x800000;

    private byte securityFlags;
    private byte requestedOplockLevel = SMB2_OPLOCK_LEVEL_NONE;
    private int impersonationLevel = SMB2_IMPERSONATION_LEVEL_IMPERSONATION;
    private long smbCreateFlags;
    private int desiredAccess = 0x00120089; // 0x80000000 | 0x1;
    private int fileAttributes;
    private int shareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE;
    private int createDisposition = FILE_OPEN;
    private int createOptions = 0;

    private String name;
    private CreateContextRequest[] createContexts;
    private String fullName;

    private String domain;

    private String server;

    private boolean resolveDfs;


    /**
     * @param config
     * @param name
     *            uncPath to open, strips a leading \
     */
    public Smb2CreateRequest ( Configuration config, String name ) {
        super(config, SMB2_CREATE);
        setPath(name);
    }


    @Override
    protected Smb2CreateResponse createResponse ( CIFSContext tc, ServerMessageBlock2Request<Smb2CreateResponse> req ) {
        return new Smb2CreateResponse(tc.getConfig(), this.name);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.RequestWithPath#getPath()
     */
    @Override
    public String getPath () {
        return '\\' + this.name;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.RequestWithPath#getFullUNCPath()
     */
    @Override
    public String getFullUNCPath () {
        return this.fullName;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.RequestWithPath#getServer()
     */
    @Override
    public String getServer () {
        return this.server;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.RequestWithPath#getDomain()
     */
    @Override
    public String getDomain () {
        return this.domain;
    }


    /**
     * @param fullName
     *            the fullName to set
     */
    @Override
    public void setFullUNCPath ( String domain, String server, String fullName ) {
        this.domain = domain;
        this.server = server;
        this.fullName = fullName;
    }


    /**
     * {@inheritDoc}
     * 
     * Strips a leading \
     *
     * @see jcifs.internal.RequestWithPath#setPath(java.lang.String)
     */
    @Override
    public void setPath ( String path ) {
        if ( path.length() > 0 && path.charAt(0) == '\\' ) {
            path = path.substring(1);
        }
        // win8.1 returns ACCESS_DENIED if the trailing backslash is included
        if ( path.length() > 1 && path.charAt(path.length() - 1) == '\\' ) {
            path = path.substring(0, path.length() - 1);
        }
        this.name = path;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.RequestWithPath#setResolveInDfs(boolean)
     */
    @Override
    public void setResolveInDfs ( boolean resolve ) {
        addFlags(SMB2_FLAGS_DFS_OPERATIONS);
        this.resolveDfs = resolve;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.RequestWithPath#isResolveInDfs()
     */
    @Override
    public boolean isResolveInDfs () {
        return this.resolveDfs;
    }


    /**
     * @param securityFlags
     *            the securityFlags to set
     */
    public void setSecurityFlags ( byte securityFlags ) {
        this.securityFlags = securityFlags;
    }


    /**
     * @param requestedOplockLevel
     *            the requestedOplockLevel to set
     */
    public void setRequestedOplockLevel ( byte requestedOplockLevel ) {
        this.requestedOplockLevel = requestedOplockLevel;
    }


    /**
     * @param impersonationLevel
     *            the impersonationLevel to set
     */
    public void setImpersonationLevel ( int impersonationLevel ) {
        this.impersonationLevel = impersonationLevel;
    }


    /**
     * @param smbCreateFlags
     *            the smbCreateFlags to set
     */
    public void setSmbCreateFlags ( long smbCreateFlags ) {
        this.smbCreateFlags = smbCreateFlags;
    }


    /**
     * @param desiredAccess
     *            the desiredAccess to set
     */
    public void setDesiredAccess ( int desiredAccess ) {
        this.desiredAccess = desiredAccess;
    }


    /**
     * @param fileAttributes
     *            the fileAttributes to set
     */
    public void setFileAttributes ( int fileAttributes ) {
        this.fileAttributes = fileAttributes;
    }


    /**
     * @param shareAccess
     *            the shareAccess to set
     */
    public void setShareAccess ( int shareAccess ) {
        this.shareAccess = shareAccess;
    }


    /**
     * @param createDisposition
     *            the createDisposition to set
     */
    public void setCreateDisposition ( int createDisposition ) {
        this.createDisposition = createDisposition;
    }


    /**
     * @param createOptions
     *            the createOptions to set
     */
    public void setCreateOptions ( int createOptions ) {
        this.createOptions = createOptions;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockRequest#size()
     */
    @Override
    public int size () {
        int size = Smb2Constants.SMB2_HEADER_LENGTH + 56;
        int nameLen = 2 * this.name.length();
        if ( nameLen == 0 ) {
            nameLen++;
        }

        size += size8(nameLen);
        if ( this.createContexts != null ) {
            for ( CreateContextRequest ccr : this.createContexts ) {
                size += size8(ccr.size());
            }
        }
        return size8(size);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#writeBytesWireFormat(byte[], int)
     */
    @Override
    protected int writeBytesWireFormat ( byte[] dst, int dstIndex ) {
        int start = dstIndex;

        if ( log.isDebugEnabled() ) {
            log.debug("Opening " + this.name);
        }

        SMBUtil.writeInt2(57, dst, dstIndex);
        dst[ dstIndex + 2 ] = this.securityFlags;
        dst[ dstIndex + 3 ] = this.requestedOplockLevel;
        dstIndex += 4;

        SMBUtil.writeInt4(this.impersonationLevel, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt8(this.smbCreateFlags, dst, dstIndex);
        dstIndex += 8;
        dstIndex += 8; // Reserved

        SMBUtil.writeInt4(this.desiredAccess, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt4(this.fileAttributes, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt4(this.shareAccess, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt4(this.createDisposition, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt4(this.createOptions, dst, dstIndex);
        dstIndex += 4;

        int nameOffsetOffset = dstIndex;
        byte[] nameBytes = this.name.getBytes(StandardCharsets.UTF_16LE);
        SMBUtil.writeInt2(nameBytes.length, dst, dstIndex + 2);
        dstIndex += 4;

        int createContextOffsetOffset = dstIndex;
        dstIndex += 4; // createContextOffset
        int createContextLengthOffset = dstIndex;
        dstIndex += 4; // createContextLength

        SMBUtil.writeInt2(dstIndex - getHeaderStart(), dst, nameOffsetOffset);

        System.arraycopy(nameBytes, 0, dst, dstIndex, nameBytes.length);
        if ( nameBytes.length == 0 ) {
            // buffer must contain at least one byte
            dstIndex++;
        }
        else {
            dstIndex += nameBytes.length;
        }

        dstIndex += pad8(dstIndex);

        if ( this.createContexts == null || this.createContexts.length == 0 ) {
            SMBUtil.writeInt4(0, dst, createContextOffsetOffset);
        }
        else {
            SMBUtil.writeInt4(dstIndex - getHeaderStart(), dst, createContextOffsetOffset);
        }
        int totalCreateContextLength = 0;
        if ( this.createContexts != null ) {
            int lastStart = -1;
            for ( CreateContextRequest createContext : this.createContexts ) {
                int structStart = dstIndex;

                SMBUtil.writeInt4(0, dst, structStart); // Next
                if ( lastStart > 0 ) {
                    // set next pointer of previous CREATE_CONTEXT
                    SMBUtil.writeInt4(structStart - dstIndex, dst, lastStart);
                }

                dstIndex += 4;
                byte[] cnBytes = createContext.getName();
                int cnOffsetOffset = dstIndex;
                SMBUtil.writeInt2(cnBytes.length, dst, dstIndex + 2);
                dstIndex += 4;

                int dataOffsetOffset = dstIndex + 2;
                dstIndex += 4;
                int dataLengthOffset = dstIndex;
                dstIndex += 4;

                SMBUtil.writeInt2(dstIndex - structStart, dst, cnOffsetOffset);
                System.arraycopy(cnBytes, 0, dst, dstIndex, cnBytes.length);
                dstIndex += cnBytes.length;
                dstIndex += pad8(dstIndex);

                SMBUtil.writeInt2(dstIndex - structStart, dst, dataOffsetOffset);
                int len = createContext.encode(dst, dstIndex);
                SMBUtil.writeInt4(len, dst, dataLengthOffset);
                dstIndex += len;

                int pad = pad8(dstIndex);
                totalCreateContextLength += len + pad;
                dstIndex += pad;
                lastStart = structStart;
            }
        }
        SMBUtil.writeInt4(totalCreateContextLength, dst, createContextLengthOffset);
        return dstIndex - start;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#readBytesWireFormat(byte[], int)
     */
    @Override
    protected int readBytesWireFormat ( byte[] buffer, int bufferIndex ) {
        return 0;
    }


    @Override
    public String toString () {
        return "[" + super.toString() + ",name=" + this.name + "]";
    }
}
