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
package jcifs.internal.smb2.ioctl;


import jcifs.Decodable;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.util.SMBUtil;


/**
 * @author mbechler
 *
 */
public class ValidateNegotiateInfoResponse implements Decodable {

    private int capabilities;
    private byte[] serverGuid = new byte[16];
    private int securityMode;
    private int dialect;


    /**
     * @return the capabilities
     */
    public int getCapabilities () {
        return this.capabilities;
    }


    /**
     * @return the serverGuid
     */
    public byte[] getServerGuid () {
        return this.serverGuid;
    }


    /**
     * @return the securityMode
     */
    public int getSecurityMode () {
        return this.securityMode;
    }


    /**
     * @return the dialect
     */
    public int getDialect () {
        return this.dialect;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Decodable#decode(byte[], int, int)
     */
    @Override
    public int decode ( byte[] buffer, int bufferIndex, int len ) throws SMBProtocolDecodingException {
        int start = bufferIndex;

        this.capabilities = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        System.arraycopy(buffer, bufferIndex, this.serverGuid, 0, 16);
        bufferIndex += 16;

        this.securityMode = SMBUtil.readInt2(buffer, bufferIndex);
        this.dialect = SMBUtil.readInt2(buffer, bufferIndex + 2);
        bufferIndex += 4;

        return bufferIndex - start;
    }

}
