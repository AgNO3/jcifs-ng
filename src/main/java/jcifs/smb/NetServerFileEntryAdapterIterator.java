/**
 * © 2017 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: Mar 24, 2017 by mbechler
 */
package jcifs.smb;

import java.net.MalformedURLException;

import jcifs.ResourceFilter;
import jcifs.SmbConstants;
import jcifs.SmbResource;

class NetServerFileEntryAdapterIterator extends FileEntryAdapterIterator {

    /**
     * @param parent
     * @param delegate
     * @param filter
     */
    public NetServerFileEntryAdapterIterator ( SmbResource parent, NetServerEnumIterator delegate, ResourceFilter filter ) {
        super(parent, delegate, filter);
    }


    /**
     * @param fe
     * @return
     * @throws MalformedURLException
     */
    @Override
    protected SmbResource adapt ( FileEntry e ) throws MalformedURLException {
        return new SmbFile(
            getParent(),
            e.getName(),
            false,
            e.getType(),
            SmbConstants.ATTR_READONLY | SmbConstants.ATTR_DIRECTORY,
            0L,
            0L,
            0L,
            0L);
    }
}