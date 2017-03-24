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

class DirFileEntryAdapterIterator extends FileEntryAdapterIterator {

    /**
     * @param parent
     * @param delegate
     * @param filter
     */
    public DirFileEntryAdapterIterator ( SmbResource parent, DirFileEntryEnumIterator delegate, ResourceFilter filter ) {
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
            this.getParent(),
            e.getName(),
            true,
            SmbConstants.TYPE_FILESYSTEM,
            e.getAttributes(),
            e.createTime(),
            e.lastModified(),
            e.lastAccess(),
            e.length());
    }
}