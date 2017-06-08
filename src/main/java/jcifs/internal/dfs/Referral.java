/*
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
package jcifs.internal.dfs;


import java.util.ArrayList;
import java.util.List;

import jcifs.Decodable;
import jcifs.RuntimeCIFSException;
import jcifs.internal.smb1.trans2.Trans2GetDfsReferralResponse;
import jcifs.internal.util.SMBUtil;
import jcifs.util.Strings;


/**
 * 
 */
public class Referral implements Decodable {

    int version;
    int size;
    int serverType;
    int rflags;
    int proximity;
    String altPath;

    int ttl;
    String rpath = null;
    String node = null;
    String specialName = null;

    String[] expandedNames = new String[0];


    /**
     * @return the version
     */
    public final int getVersion () {
        return this.version;
    }


    /**
     * @return the size
     */
    public final int getSize () {
        return this.size;
    }


    /**
     * @return the serverType
     */
    public final int getServerType () {
        return this.serverType;
    }


    /**
     * @return the rflags
     */
    public final int getRFlags () {
        return this.rflags;
    }


    /**
     * @return the proximity
     */
    public final int getProximity () {
        return this.proximity;
    }


    /**
     * @return the altPath
     */
    public final String getAltPath () {
        return this.altPath;
    }


    /**
     * @return the ttl
     */
    public final int getTtl () {
        return this.ttl;
    }


    /**
     * @return the rpath
     */
    public final String getRpath () {
        return this.rpath;
    }


    /**
     * @return the node
     */
    public final String getNode () {
        return this.node;
    }


    /**
     * @return the specialName
     */
    public final String getSpecialName () {
        return this.specialName;
    }


    /**
     * @return the expandedNames
     */
    public final String[] getExpandedNames () {
        return this.expandedNames;
    }


    @Override
    public int decode ( byte[] buffer, int bufferIndex, int len ) {
        int start = bufferIndex;

        this.version = SMBUtil.readInt2(buffer, bufferIndex);
        if ( this.version != 3 && this.version != 1 ) {
            throw new RuntimeCIFSException("Version " + this.version + " referral not supported. Please report this to jcifs at samba dot org.");
        }
        bufferIndex += 2;
        this.size = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.serverType = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.rflags = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        if ( this.version == 3 ) {
            this.proximity = SMBUtil.readInt2(buffer, bufferIndex);
            bufferIndex += 2;
            this.ttl = SMBUtil.readInt2(buffer, bufferIndex);
            bufferIndex += 2;

            if ( ( this.rflags & Trans2GetDfsReferralResponse.FLAGS_NAME_LIST_REFERRAL ) == 0 ) {
                int pathOffset = SMBUtil.readInt2(buffer, bufferIndex);
                bufferIndex += 2;
                int altPathOffset = SMBUtil.readInt2(buffer, bufferIndex);
                bufferIndex += 2;
                int nodeOffset = SMBUtil.readInt2(buffer, bufferIndex);
                bufferIndex += 2;

                if ( pathOffset > 0 ) {
                    this.rpath = readString(buffer, start + pathOffset, len);
                }
                if ( nodeOffset > 0 ) {
                    this.node = readString(buffer, start + nodeOffset, len);
                }
                if ( altPathOffset > 0 ) {
                    this.altPath = readString(buffer, start + altPathOffset, len);
                }
            }
            else {
                int specialNameOffset = SMBUtil.readInt2(buffer, bufferIndex);
                bufferIndex += 2;
                int numExpanded = SMBUtil.readInt2(buffer, bufferIndex);
                bufferIndex += 2;
                int expandedNameOffset = SMBUtil.readInt2(buffer, bufferIndex);
                bufferIndex += 2;

                if ( specialNameOffset > 0 ) {
                    this.specialName = readString(buffer, start + specialNameOffset, len);
                }

                if ( expandedNameOffset > 0 ) {
                    List<String> names = new ArrayList<>();
                    for ( int i = 0; i < numExpanded; i++ ) {
                        String en = readString(buffer, start + expandedNameOffset, len);
                        names.add(en);
                        expandedNameOffset += en.length() * 2 + 2;
                    }
                    this.expandedNames = names.toArray(new String[names.size()]);
                }

            }
        }
        else if ( this.version == 1 ) {
            this.node = readString(buffer, bufferIndex, len);
        }

        return this.size;
    }


    private static String readString ( byte[] buffer, int bufferIndex, int len ) {
        // this is not absolutely correct, but we assume that the header is aligned
        if ( ( bufferIndex % 2 ) != 0 ) {
            bufferIndex++;
        }
        return Strings.fromUNIBytes(buffer, bufferIndex, Strings.findUNITermination(buffer, bufferIndex, len));
    }


    @Override
    public String toString () {
        return new String(
            "Referral[" + "version=" + this.version + ",size=" + this.size + ",serverType=" + this.serverType + ",flags=" + this.rflags
                    + ",proximity=" + this.proximity + ",ttl=" + this.ttl + ",path=" + this.rpath + ",altPath=" + this.altPath + ",node=" + this.node
                    + "]");
    }
}