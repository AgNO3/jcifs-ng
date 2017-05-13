/**
 * © 2017 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: May 13, 2017 by mbechler
 */
package jcifs.internal.smb1.trans2;

import jcifs.internal.AllocInfo;

class SmbInfoAllocation implements AllocInfo {

    long alloc; // Also handles SmbQueryFSSizeInfo
    long free;
    int sectPerAlloc;
    int bytesPerSect;


    @Override
    public long getCapacity () {
        return this.alloc * this.sectPerAlloc * this.bytesPerSect;
    }


    @Override
    public long getFree () {
        return this.free * this.sectPerAlloc * this.bytesPerSect;
    }


    @Override
    public String toString () {
        return new String(
            "SmbInfoAllocation[" + "alloc=" + this.alloc + ",free=" + this.free + ",sectPerAlloc=" + this.sectPerAlloc + ",bytesPerSect="
                    + this.bytesPerSect + "]");
    }
}