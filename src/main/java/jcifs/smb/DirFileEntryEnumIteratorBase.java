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


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSException;
import jcifs.CloseableIterator;
import jcifs.ResourceNameFilter;
import jcifs.SmbResource;


/**
 * @author mbechler
 *
 */
public abstract class DirFileEntryEnumIteratorBase implements CloseableIterator<FileEntry> {

    private static final Logger log = LoggerFactory.getLogger(DirFileEntryEnumIteratorBase.class);

    private final SmbTreeHandleImpl treeHandle;
    private final ResourceNameFilter nameFilter;
    private final SmbResource parent;
    private final String wildcard;
    private final int searchAttributes;
    private FileEntry next;
    private int ridx;

    private boolean closed = false;


    /**
     * @param th
     * @param parent
     * @param wildcard
     * @param filter
     * @param searchAttributes
     * @throws CIFSException
     * 
     */
    public DirFileEntryEnumIteratorBase ( SmbTreeHandleImpl th, SmbResource parent, String wildcard, ResourceNameFilter filter, int searchAttributes )
            throws CIFSException {
        this.parent = parent;
        this.wildcard = wildcard;
        this.nameFilter = filter;
        this.searchAttributes = searchAttributes;

        this.treeHandle = th.acquire();
        try {
            this.next = open();
            if ( this.next == null ) {
                doClose();
            }
        }
        catch ( Exception e ) {
            doClose();
            throw e;
        }

    }


    /**
     * @return the treeHandle
     */
    public final SmbTreeHandleImpl getTreeHandle () {
        return this.treeHandle;
    }


    /**
     * @return the searchAttributes
     */
    public final int getSearchAttributes () {
        return this.searchAttributes;
    }


    /**
     * @return the wildcard
     */
    public final String getWildcard () {
        return this.wildcard;
    }


    /**
     * @return the parent
     */
    public final SmbResource getParent () {
        return this.parent;
    }


    private final boolean filter ( FileEntry fe ) {
        String name = fe.getName();
        if ( name.length() < 3 ) {
            int h = name.hashCode();
            if ( h == SmbFile.HASH_DOT || h == SmbFile.HASH_DOT_DOT ) {
                if ( name.equals(".") || name.equals("..") )
                    return false;
            }
        }
        if ( this.nameFilter == null ) {
            return true;
        }
        try {
            if ( !this.nameFilter.accept(this.parent, name) ) {
                return false;
            }
            return true;
        }
        catch ( CIFSException e ) {
            log.error("Failed to apply name filter", e);
            return false;
        }
    }


    protected final FileEntry advance ( boolean last ) throws CIFSException {
        FileEntry[] results = getResults();
        while ( this.ridx < results.length ) {
            FileEntry itm = results[ this.ridx ];
            this.ridx++;
            if ( filter(itm) ) {
                return itm;
            }
        }

        if ( !last && !isDone() ) {
            if ( !fetchMore() ) {
                doClose();
                return null;
            }
            this.ridx = 0;
            return advance(true);
        }
        return null;
    }


    protected abstract FileEntry open () throws CIFSException;


    protected abstract boolean isDone ();


    protected abstract boolean fetchMore () throws CIFSException;


    protected abstract FileEntry[] getResults ();


    /**
     * 
     */
    protected synchronized void doClose () throws CIFSException {
        // otherwise already closed
        if ( !this.closed ) {
            this.closed = true;
            try {
                doCloseInternal();
            }
            finally {
                this.next = null;
                this.treeHandle.release();
            }
        }
    }


    /**
     * 
     */
    protected abstract void doCloseInternal () throws CIFSException;


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
    public FileEntry next () {
        FileEntry n = this.next;
        try {
            FileEntry ne = advance(false);
            if ( ne == null ) {
                doClose();
                return n;
            }
            this.next = ne;
        }
        catch ( CIFSException e ) {
            log.warn("Enumeration failed", e);
            this.next = null;
            try {
                doClose();
            }
            catch ( CIFSException e1 ) {
                log.debug("Failed to close enum", e);
            }
        }
        return n;
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.AutoCloseable#close()
     */
    @Override
    public void close () throws CIFSException {
        if ( this.next != null ) {
            doClose();
        }
    }


    @Override
    public void remove () {
        throw new UnsupportedOperationException("remove");
    }
}
