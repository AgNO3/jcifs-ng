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
import jcifs.internal.smb1.com.SmbComBlankResponse;
import jcifs.internal.smb1.com.SmbComFindClose2;
import jcifs.internal.smb1.trans.SmbComTransaction;
import jcifs.internal.smb1.trans2.Trans2FindFirst2;
import jcifs.internal.smb1.trans2.Trans2FindFirst2Response;
import jcifs.internal.smb1.trans2.Trans2FindNext2;


class DirFileEntryEnumIterator implements CloseableIterator<FileEntry> {

    private static final Logger log = LoggerFactory.getLogger(DirFileEntryEnumIterator.class);

    private final Trans2FindFirst2 firstRequest;
    private final Trans2FindNext2 nextRequest;
    private final Trans2FindFirst2Response response;
    private final SmbTreeHandleImpl treeHandle;
    private final ResourceNameFilter nameFilter;
    private final SmbResource parent;
    private FileEntry next;
    private int ridx;


    /**
     * @param th
     * @param parent
     * @param wildcard
     * @param filter
     * @param searchAttributes
     * @param batchCount
     * @param batchSize
     * @throws CIFSException
     * 
     */
    public DirFileEntryEnumIterator ( SmbTreeHandleImpl th, SmbResource parent, String wildcard, ResourceNameFilter filter, int searchAttributes,
            int batchCount, int batchSize ) throws CIFSException {
        this.parent = parent;
        this.nameFilter = filter;
        String unc = parent.getLocator().getUNCPath();
        String p = parent.getLocator().getURL().getPath();
        if ( p.lastIndexOf('/') != ( p.length() - 1 ) ) {
            throw new SmbException(parent.getLocator().getURL() + " directory must end with '/'");
        }

        this.firstRequest = new Trans2FindFirst2(th.getConfig(), unc, wildcard, searchAttributes, batchCount, batchSize);
        this.response = new Trans2FindFirst2Response(th.getConfig());
        this.treeHandle = th.acquire();
        try {
            this.next = open();
        }
        catch ( Exception e ) {
            this.treeHandle.release();
            throw e;
        }

        this.nextRequest = new Trans2FindNext2(
            th.getConfig(),
            this.response.getSid(),
            this.response.getResumeKey(),
            this.response.getLastName(),
            batchCount,
            batchSize);
        this.response.setSubCommand(SmbComTransaction.TRANS2_FIND_NEXT2);
    }


    private final FileEntry open () throws CIFSException {
        this.treeHandle.send(this.firstRequest, this.response);
        FileEntry n = advance();
        if ( n == null ) {
            doClose();
        }
        return n;
    }


    private final FileEntry advance () throws CIFSException {
        while ( this.ridx < this.response.getNumEntries() ) {
            FileEntry itm = this.response.getResults()[ this.ridx ];
            this.ridx++;
            if ( filter(itm) ) {
                return itm;
            }
        }

        if ( !this.response.isEndOfSearch() ) {
            this.nextRequest.reset(this.response.getResumeKey(), this.response.getLastName());
            this.response.reset();
            this.treeHandle.send(this.nextRequest, this.response);
            this.ridx = 0;
            return advance();
        }
        return null;
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
            FileEntry ne = advance();
            if ( ne == null ) {
                doClose();
                return n;
            }
            this.next = ne;
        }
        catch ( CIFSException e ) {
            log.warn("Enumeration failed", e);
            this.next = null;
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


    /**
     * @throws CIFSException
     */
    private void doClose () throws CIFSException {
        try {
            this.treeHandle.send(
                new SmbComFindClose2(this.treeHandle.getConfig(), this.response.getSid()),
                new SmbComBlankResponse(this.treeHandle.getConfig()));
        }
        catch ( SmbException se ) {
            log.debug("SmbComFindClose2 failed", se);
        }
        finally {
            this.treeHandle.release();
            this.next = null;
        }
    }

}