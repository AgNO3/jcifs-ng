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
package jcifs.internal.smb2.session;


import jcifs.CIFSContext;
import jcifs.internal.smb2.ServerMessageBlock2;
import jcifs.internal.smb2.ServerMessageBlock2Request;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.util.SMBUtil;


/**
 * @author mbechler
 *
 */
public class Smb2SessionSetupRequest extends ServerMessageBlock2Request<Smb2SessionSetupResponse> {

    private byte[] token;
    private int capabilities;
    private boolean sessionBinding;
    private long previousSessionId;
    private int securityMode;


    /**
     * @param context
     * @param securityMode
     * @param capabilities
     * @param previousSessionid
     * @param token
     */
    public Smb2SessionSetupRequest ( CIFSContext context, int securityMode, int capabilities, long previousSessionid, byte[] token ) {
        super(context.getConfig(), SMB2_SESSION_SETUP);
        this.securityMode = securityMode;
        this.capabilities = capabilities;
        this.previousSessionId = previousSessionid;
        this.token = token;
    }


    @Override
    protected Smb2SessionSetupResponse createResponse ( CIFSContext tc, ServerMessageBlock2Request<Smb2SessionSetupResponse> req ) {
        return new Smb2SessionSetupResponse(tc.getConfig());
    }


    /**
     * @param sessionBinding
     *            the sessionBinding to set
     */
    public void setSessionBinding ( boolean sessionBinding ) {
        this.sessionBinding = sessionBinding;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#chain(jcifs.internal.smb2.ServerMessageBlock2)
     */
    @Override
    public boolean chain ( ServerMessageBlock2 n ) {
        n.setSessionId(Smb2Constants.UNSPECIFIED_SESSIONID);
        return super.chain(n);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockRequest#size()
     */
    @Override
    public int size () {
        return size8(Smb2Constants.SMB2_HEADER_LENGTH + 24 + ( this.token != null ? this.token.length : 0 ));
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#writeBytesWireFormat(byte[], int)
     */
    @Override
    protected int writeBytesWireFormat ( byte[] dst, int dstIndex ) {
        int start = dstIndex;

        SMBUtil.writeInt2(25, dst, dstIndex);

        dst[ dstIndex + 2 ] = (byte) ( this.sessionBinding ? 0x1 : 0 );
        dst[ dstIndex + 3 ] = (byte) ( this.securityMode );
        dstIndex += 4;

        SMBUtil.writeInt4(this.capabilities, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt4(0, dst, dstIndex); // Channel
        dstIndex += 4;

        int offsetOffset = dstIndex;
        dstIndex += 2;
        SMBUtil.writeInt2(this.token != null ? this.token.length : 0, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt8(this.previousSessionId, dst, dstIndex);
        dstIndex += 8;
        SMBUtil.writeInt2(dstIndex - getHeaderStart(), dst, offsetOffset);

        dstIndex += pad8(dstIndex);

        if ( this.token != null ) {
            System.arraycopy(this.token, 0, dst, dstIndex, this.token.length);
            dstIndex += this.token.length;
        }

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

}
