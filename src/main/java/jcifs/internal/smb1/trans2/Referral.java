/**
 * © 2017 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: May 13, 2017 by mbechler
 */
package jcifs.internal.smb1.trans2;


import java.util.ArrayList;
import java.util.List;

import jcifs.RuntimeCIFSException;
import jcifs.internal.util.SMBUtil;


/**
 * 
 */
public class Referral {

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


    int readWireFormat ( Trans2GetDfsReferralResponse resp, byte[] buffer, int bufferIndex, int len, boolean unicode ) {
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
                    this.rpath = resp.readString(buffer, start + pathOffset, len, unicode);
                }
                if ( nodeOffset > 0 ) {
                    this.node = resp.readString(buffer, start + nodeOffset, len, unicode);
                }
                if ( altPathOffset > 0 ) {
                    this.altPath = resp.readString(buffer, start + altPathOffset, len, unicode);
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
                    this.specialName = resp.readString(buffer, start + specialNameOffset, len, unicode);
                }

                if ( expandedNameOffset > 0 ) {
                    List<String> names = new ArrayList<>();
                    for ( int i = 0; i < numExpanded; i++ ) {
                        String en = resp.readString(buffer, start + expandedNameOffset, len, unicode);
                        names.add(en);
                        expandedNameOffset += resp.stringWireLength(en, start + expandedNameOffset);
                    }
                    this.expandedNames = names.toArray(new String[names.size()]);
                }

            }
        }
        else if ( this.version == 1 ) {
            this.node = resp.readString(buffer, bufferIndex, len, unicode);
        }

        return this.size;
    }


    @Override
    public String toString () {
        return new String(
            "Referral[" + "version=" + this.version + ",size=" + this.size + ",serverType=" + this.serverType + ",flags=" + this.rflags
                    + ",proximity=" + this.proximity + ",ttl=" + this.ttl + ",path=" + this.rpath + ",altPath=" + this.altPath + ",node=" + this.node
                    + "]");
    }
}