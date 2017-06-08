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

package jcifs.internal.dtyp;


import java.io.IOException;

import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.util.SMBUtil;
import jcifs.smb.SID;


/**
 * Internal use only
 * 
 * @internal
 */
public class SecurityDescriptor implements SecurityInfo {

    /**
     * Descriptor type
     */
    private int type;

    /**
     * ACEs
     */
    private ACE[] aces;
    private SID ownerUserSid, ownerGroupSid;


    /**
     * 
     */
    public SecurityDescriptor () {}


    /**
     * @param buffer
     * @param bufferIndex
     * @param len
     * @throws IOException
     */
    public SecurityDescriptor ( byte[] buffer, int bufferIndex, int len ) throws IOException {
        this.decode(buffer, bufferIndex, len);
    }


    /**
     * @return the type
     */
    public final int getType () {
        return this.type;
    }


    /**
     * @return the aces
     */
    public final ACE[] getAces () {
        return this.aces;
    }


    /**
     * @return the ownerGroupSid
     */
    public final SID getOwnerGroupSid () {
        return this.ownerGroupSid;
    }


    /**
     * @return the ownerUserSid
     */
    public final SID getOwnerUserSid () {
        return this.ownerUserSid;
    }


    /**
     * 
     * @param buffer
     * @param bufferIndex
     * @param len
     * @return decoded data length
     * @throws SMBProtocolDecodingException
     */
    @Override
    public int decode ( byte[] buffer, int bufferIndex, int len ) throws SMBProtocolDecodingException {
        int start = bufferIndex;

        bufferIndex++; // revision
        bufferIndex++;
        this.type = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        int ownerUOffset = SMBUtil.readInt4(buffer, bufferIndex); // offset to owner sid
        bufferIndex += 4;
        int ownerGOffset = SMBUtil.readInt4(buffer, bufferIndex); // offset to group sid
        bufferIndex += 4;
        SMBUtil.readInt4(buffer, bufferIndex); // offset to sacl
        bufferIndex += 4;
        int daclOffset = SMBUtil.readInt4(buffer, bufferIndex);

        if ( ownerUOffset > 0 ) {
            bufferIndex = start + ownerUOffset;
            this.ownerUserSid = new SID(buffer, bufferIndex);
            bufferIndex += 8 + 4 * this.ownerUserSid.sub_authority_count;
        }

        if ( ownerGOffset > 0 ) {
            bufferIndex = start + ownerGOffset;
            this.ownerGroupSid = new SID(buffer, bufferIndex);
            bufferIndex += 8 + 4 * this.ownerGroupSid.sub_authority_count;
        }

        bufferIndex = start + daclOffset;

        if ( daclOffset > 0 ) {
            bufferIndex++; // revision
            bufferIndex++;
            SMBUtil.readInt2(buffer, bufferIndex);
            bufferIndex += 2;
            int numAces = SMBUtil.readInt4(buffer, bufferIndex);
            bufferIndex += 4;

            if ( numAces > 4096 )
                throw new SMBProtocolDecodingException("Invalid SecurityDescriptor");

            this.aces = new ACE[numAces];
            for ( int i = 0; i < numAces; i++ ) {
                this.aces[ i ] = new ACE();
                bufferIndex += this.aces[ i ].decode(buffer, bufferIndex, len - bufferIndex);
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
