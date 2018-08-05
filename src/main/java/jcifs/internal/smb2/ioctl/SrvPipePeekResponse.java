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
 * @author svella
 *
 */
public class SrvPipePeekResponse implements Decodable {

    // see https://msdn.microsoft.com/en-us/library/dd414577.aspx

    private int namedPipeState;
    private int readDataAvailable;
    private int numberOfMessages;
    private int messageLength;
    private byte[] data;


    /**
     * @return the chunkBytesWritten
     */
    public int getNamedPipeState () {
        return this.namedPipeState;
    }


    /**
     * @return the chunksWritten
     */
    public int getReadDataAvailable () {
        return this.readDataAvailable;
    }


    /**
     * @return the totalBytesWritten
     */
    public int getNumberOfMessages () {
        return this.numberOfMessages;
    }


    /**
     * @return the totalBytesWritten
     */
    public int getMessageLength () {
        return this.messageLength;
    }


    /**
     * @return the totalBytesWritten
     */
    public byte[] getData () {
        return this.data;
    }


    /**
     * {@inheritDoc}
     *
     * @see Decodable#decode(byte[], int, int)
     */
    @Override
    public int decode ( byte[] buffer, int bufferIndex, int len ) throws SMBProtocolDecodingException {
        int start = bufferIndex;
        this.namedPipeState = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.readDataAvailable = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.numberOfMessages = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.messageLength = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.data = new byte[len - 16];
        if ( this.data.length > 0 ) {
            System.arraycopy(buffer, bufferIndex, this.data, 0, this.data.length);
        }
        return bufferIndex - start;
    }

}
