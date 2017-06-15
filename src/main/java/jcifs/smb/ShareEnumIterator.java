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
import java.util.Iterator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSException;
import jcifs.CloseableIterator;
import jcifs.ResourceFilter;
import jcifs.SmbConstants;
import jcifs.SmbResource;


class ShareEnumIterator implements CloseableIterator<SmbResource> {

    private static final Logger log = LoggerFactory.getLogger(ShareEnumIterator.class);

    private final Iterator<FileEntry> delegate;
    private final ResourceFilter filter;
    private final SmbResource parent;
    private SmbResource next;


    /**
     * @param parent
     * @param delegate
     * @param filter
     * 
     */
    public ShareEnumIterator ( SmbResource parent, Iterator<FileEntry> delegate, ResourceFilter filter ) {
        this.parent = parent;
        this.delegate = delegate;
        this.filter = filter;
        this.next = advance();
    }


    /**
     * @return next element
     */
    private SmbResource advance () {
        while ( this.delegate.hasNext() ) {
            FileEntry n = this.delegate.next();
            if ( this.filter == null ) {
                try {
                    return adapt(n);
                }
                catch ( MalformedURLException e ) {
                    log.error("Failed to create child URL", e);
                    continue;
                }
            }
            try ( SmbResource nr = adapt(n) ) {
                if ( !this.filter.accept(nr) ) {
                    continue;
                }
                return nr;
            }
            catch ( CIFSException e ) {
                log.error("Failed to apply filter", e);
                continue;
            }
            catch ( MalformedURLException e ) {
                log.error("Failed to create child URL", e);
                continue;
            }
        }
        return null;
    }


    private SmbResource adapt ( FileEntry e ) throws MalformedURLException {
        return new SmbFile(this.parent, e.getName(), false, e.getType(), SmbConstants.ATTR_READONLY | SmbConstants.ATTR_DIRECTORY, 0L, 0L, 0L, 0L);
    }


    /**
     * {@inheritDoc}
     *
     * @see java.util.Iterator#hasNext()
     */
    @Override
    public boolean hasNext () {
        return this.next != null;
    }


    /**
     * {@inheritDoc}
     *
     * @see java.util.Iterator#next()
     */
    @Override
    public SmbResource next () {
        SmbResource n = this.next;
        this.next = advance();
        return n;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.CloseableIterator#close()
     */
    @Override
    public void close () {
        // nothing to clean up
        this.next = null;
    }

    @Override
    public void remove() {
        throw new UnsupportedOperationException("remove");
    }
}