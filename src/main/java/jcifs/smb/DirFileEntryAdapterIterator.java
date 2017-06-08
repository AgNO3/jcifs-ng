/*
 * © 2017 AgNO3 Gmbh & Co. KG
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


import java.net.MalformedURLException;

import jcifs.CloseableIterator;
import jcifs.ResourceFilter;
import jcifs.SmbConstants;
import jcifs.SmbResource;


class DirFileEntryAdapterIterator extends FileEntryAdapterIterator {

    /**
     * @param parent
     * @param delegate
     * @param filter
     */
    public DirFileEntryAdapterIterator ( SmbResource parent, CloseableIterator<FileEntry> delegate, ResourceFilter filter ) {
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
            true,
            SmbConstants.TYPE_FILESYSTEM,
            e.getAttributes(),
            e.createTime(),
            e.lastModified(),
            e.lastAccess(),
            e.length());
    }
}