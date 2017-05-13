/*
 * © 2016 AgNO3 Gmbh & Co. KG
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

package jcifs.internal.smb1.trans.nt;


import java.io.IOException;

import jcifs.FileNotifyInformation;
import jcifs.internal.util.SMBUtil;
import jcifs.util.Hexdump;
import jcifs.util.Strings;


/**
 * File notification information
 * 
 * 
 * @author mbechler
 *
 */
class FileNotifyInformationImpl implements FileNotifyInformation {

    int nextEntryOffset;
    int action;
    int fileNameLength;
    String fileName;


    /**
     * 
     */
    public FileNotifyInformationImpl () {}


    @Override
    public int getAction () {
        return this.action;
    }


    @Override
    public String getFileName () {
        return this.fileName;
    }


    /**
     * 
     * @param buffer
     * @param bufferIndex
     * @param len
     * @throws IOException
     */
    public FileNotifyInformationImpl ( byte[] buffer, int bufferIndex, int len ) throws IOException {
        this.decode(buffer, bufferIndex, len);
    }


    protected int decode ( byte[] buffer, int bufferIndex, int len ) throws IOException {
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
