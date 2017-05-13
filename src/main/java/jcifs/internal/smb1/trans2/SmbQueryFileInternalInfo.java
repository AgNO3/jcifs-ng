/**
 * © 2017 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: May 13, 2017 by mbechler
 */
package jcifs.internal.smb1.trans2;

class SmbQueryFileInternalInfo {

    long indexNumber;


    /**
     * @return the indexNumber
     */
    public long getIndexNumber () {
        return this.indexNumber;
    }


    @Override
    public String toString () {
        return new String("SmbQueryFileInternalInfo[" + "indexNumber=" + this.indexNumber + "]");
    }
}