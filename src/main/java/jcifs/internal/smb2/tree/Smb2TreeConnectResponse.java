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
package jcifs.internal.smb2.tree;


import jcifs.Configuration;
import jcifs.internal.CommonServerMessageBlockRequest;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.TreeConnectResponse;
import jcifs.internal.smb2.ServerMessageBlock2;
import jcifs.internal.smb2.ServerMessageBlock2Response;
import jcifs.internal.util.SMBUtil;


/**
 * @author mbechler
 *
 */
public class Smb2TreeConnectResponse extends ServerMessageBlock2Response implements TreeConnectResponse {

    /**
     * 
     */
    public static final byte SMB2_SHARE_TYPE_DISK = 0x1;
    /**
     * 
     */
    public static final byte SMB2_SHARE_TYPE_PIPE = 0x2;
    /**
     * 
     */
    public static final byte SMB2_SHARE_TYPE_PRINT = 0x3;

    /**
     * 
     */
    public static final int SMB2_SHAREFLAG_MANUAL_CACHING = 0x0;
    /**
     * 
     */
    public static final int SMB2_SHAREFLAG_AUTO_CACHING = 0x10;
    /**
     * 
     */
    public static final int SMB2_SHAREFLAG_VDO_CACHING = 0x20;

    /**
     * 
     */
    public static final int SMB2_SHAREFLAG_DFS = 0x1;
    /**
     * 
     */
    public static final int SMB2_SHAREFLAG_DFS_ROOT = 0x2;

    /**
     * 
     */
    public static final int SMB2_SHAREFLAG_RESTRICT_EXCLUSIVE_OPENS = 0x100;
    /**
     * 
     */
    public static final int SMB2_SHAREFLAG_FORCE_SHARED_DELETE = 0x200;
    /**
     * 
     */
    public static final int SMB2_SHAREFLAG_ALLOW_NAMESPACE_CACHING = 0x400;
    /**
     * 
     */
    public static final int SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM = 0x800;
    /**
     * 
     */
    public static final int SMB2_SHAREFLAG_FORCE_LEVEL2_OPLOCK = 0x1000;
    /**
     * 
     */
    public static final int SMB2_SHAREFLAG_ENABLE_HASH_V1 = 0x2000;
    /**
     * 
     */
    public static final int SMB2_SHAREFLAG_ENABLE_HASH_V2 = 0x4000;
    /**
     * 
     */
    public static final int SMB2_SHAREFLAG_ENCRYPT_DATA = 0x8000;

    /**
     * 
     */
    public static final int SMB2_SHARE_CAP_DFS = 0x8;

    /**
     * 
     */
    public static final int SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY = 0x10;

    /**
     * 
     */
    public static final int SMB2_SHARE_CAP_SCALEOUT = 0x20;

    /**
     * 
     */
    public static final int SMB2_SHARE_CAP_CLUSTER = 0x40;

    /**
     * 
     */
    public static final int SMB2_SHARE_CAP_ASYMMETRIC = 0x80;

    private byte shareType;
    private int shareFlags;
    private int capabilities;
    private int maximalAccess;


    /**
     * @param config
     */
    public Smb2TreeConnectResponse ( Configuration config ) {
        super(config);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2Response#prepare(jcifs.internal.CommonServerMessageBlockRequest)
     */
    @Override
    public void prepare ( CommonServerMessageBlockRequest next ) {
        if ( isReceived() ) {
            ( (ServerMessageBlock2) next ).setTreeId(getTreeId());
        }
        super.prepare(next);
    }


    /**
     * @return the shareType
     */
    public byte getShareType () {
        return this.shareType;
    }


    /**
     * @return the shareFlags
     */
    public int getShareFlags () {
        return this.shareFlags;
    }


    /**
     * @return the capabilities
     */
    public int getCapabilities () {
        return this.capabilities;
    }


    /**
     * @return the maximalAccess
     */
    public int getMaximalAccess () {
        return this.maximalAccess;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.TreeConnectResponse#getTid()
     */
    @Override
    public final int getTid () {
        return getTreeId();
    }


    @Override
    public boolean isValidTid () {
        return getTreeId() != 0;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.TreeConnectResponse#getService()
     */
    @Override
    public String getService () {
        return null;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.TreeConnectResponse#isShareDfs()
     */
    @Override
    public boolean isShareDfs () {
        return ( this.shareFlags & ( SMB2_SHAREFLAG_DFS | SMB2_SHAREFLAG_DFS_ROOT ) ) != 0
                || ( this.capabilities & SMB2_SHARE_CAP_DFS ) == SMB2_SHARE_CAP_DFS;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#writeBytesWireFormat(byte[], int)
     */
    @Override
    protected int writeBytesWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    /**
     * {@inheritDoc}
     * 
     * @throws Smb2ProtocolDecodingException
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#readBytesWireFormat(byte[], int)
     */
    @Override
    protected int readBytesWireFormat ( byte[] buffer, int bufferIndex ) throws SMBProtocolDecodingException {
        int start = bufferIndex;
        int structureSize = SMBUtil.readInt2(buffer, bufferIndex);
        if ( structureSize != 16 ) {
            throw new SMBProtocolDecodingException("Structure size is not 16");
        }

        this.shareType = buffer[ bufferIndex + 2 ];
        bufferIndex += 4;
        this.shareFlags = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.capabilities = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.maximalAccess = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        return bufferIndex - start;
    }

}
