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


import java.io.ByteArrayOutputStream;
import java.io.IOException;

import jcifs.Configuration;
import jcifs.RuntimeCIFSException;
import jcifs.util.Strings;


class SmbComNegotiate extends ServerMessageBlock {

    private String[] dialects;


    SmbComNegotiate ( Configuration config ) {
        super(config);
        this.command = SMB_COM_NEGOTIATE;
        this.flags2 = config.getFlags2();
        this.dialects = config.getSupportedDialects();
    }


    @Override
    int writeParameterWordsWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    int writeBytesWireFormat ( byte[] dst, int dstIndex ) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        for ( String dialect : this.dialects ) {
            bos.write(0x02);
            try {
                bos.write(Strings.getASCIIBytes(dialect));
            }
            catch ( IOException e ) {
                throw new RuntimeCIFSException(e);
            }
            bos.write(0x0);
        }

        System.arraycopy(bos.toByteArray(), 0, dst, dstIndex, bos.size());
        return bos.size();
    }


    @Override
    int readParameterWordsWireFormat ( byte[] buffer, int bufferIndex ) {
        return 0;
    }


    @Override
    int readBytesWireFormat ( byte[] buffer, int bufferIndex ) {
        return 0;
    }


    @Override
    public String toString () {
        return new String("SmbComNegotiate[" + super.toString() + ",wordCount=" + this.wordCount + ",dialects=NT LM 0.12]");
    }
}
