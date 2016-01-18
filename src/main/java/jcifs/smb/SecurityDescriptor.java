/* jcifs smb client library in Java
 * Copyright (C) 2005  "Michael B. Allen" <jcifs at samba dot org>
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


import java.io.IOException;


public class SecurityDescriptor {

    public int type;
    public ACE[] aces;


    public SecurityDescriptor () {}


    public SecurityDescriptor ( byte[] buffer, int bufferIndex, int len ) throws IOException {
        this.decode(buffer, bufferIndex, len);
    }


    public int decode ( byte[] buffer, int bufferIndex, int len ) throws IOException {
        int start = bufferIndex;

        bufferIndex++; // revision
        bufferIndex++;
        this.type = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        SMBUtil.readInt4(buffer, bufferIndex); // offset to owner sid
        bufferIndex += 4;
        SMBUtil.readInt4(buffer, bufferIndex); // offset to group sid
        bufferIndex += 4;
        SMBUtil.readInt4(buffer, bufferIndex); // offset to sacl
        bufferIndex += 4;
        int daclOffset = SMBUtil.readInt4(buffer, bufferIndex);

        bufferIndex = start + daclOffset;

        bufferIndex++; // revision
        bufferIndex++;
        SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        int numAces = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        if ( numAces > 4096 )
            throw new IOException("Invalid SecurityDescriptor");

        if ( daclOffset != 0 ) {
            this.aces = new ACE[numAces];
            for ( int i = 0; i < numAces; i++ ) {
                this.aces[ i ] = new ACE();
                bufferIndex += this.aces[ i ].decode(buffer, bufferIndex);
            }
        }
        else {
            this.aces = null;
        }

        return bufferIndex - start;
    }


    @Override
    public String toString () {
        String ret = "SecurityDescriptor:\n";
        if ( this.aces != null ) {
            for ( int ai = 0; ai < this.aces.length; ai++ ) {
                ret += this.aces[ ai ].toString() + "\n";
            }
        }
        else {
            ret += "NULL";
        }
        return ret;
    }
}
