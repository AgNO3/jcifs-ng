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
import jcifs.ResourceNameFilter;
import jcifs.SmbResource;
import jcifs.internal.smb2.create.Smb2CloseRequest;
import jcifs.internal.smb2.create.Smb2CreateRequest;
import jcifs.internal.smb2.create.Smb2CreateResponse;
import jcifs.internal.smb2.info.Smb2QueryDirectoryRequest;
import jcifs.internal.smb2.info.Smb2QueryDirectoryResponse;


/**
 * @author mbechler
 *
 */
public class DirFileEntryEnumIterator2 extends DirFileEntryEnumIteratorBase {

    private static final Logger log = LoggerFactory.getLogger(DirFileEntryEnumIterator2.class);

    private byte[] fileId;
    private Smb2QueryDirectoryResponse response;


    /**
     * @param th
     * @param parent
     * @param wildcard
     * @param filter
     * @param searchAttributes
     * @throws CIFSException
     */
    public DirFileEntryEnumIterator2 ( SmbTreeHandleImpl th, SmbResource parent, String wildcard, ResourceNameFilter filter, int searchAttributes )
            throws CIFSException {
        super(th, parent, wildcard, filter, searchAttributes);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.DirFileEntryEnumIteratorBase#getResults()
     */
    @Override
    protected FileEntry[] getResults () {
        FileEntry[] results = this.response.getResults();
        if ( results == null ) {
            return new FileEntry[0];
        }
        return results;
    }


    /**
     * @param th
     * @param parent
     * @param wildcard
     * @return
     * @throws CIFSException
     */
    @SuppressWarnings ( "resource" )
    @Override
    protected FileEntry open () throws CIFSException {
        SmbTreeHandleImpl th = getTreeHandle();
        String uncPath = getParent().getLocator().getUNCPath();
        Smb2CreateRequest create = new Smb2CreateRequest(th.getConfig(), uncPath);
        create.setCreateOptions(Smb2CreateRequest.FILE_DIRECTORY_FILE);
        Smb2QueryDirectoryRequest query = new Smb2QueryDirectoryRequest(th.getConfig());
        query.setFileName(getWildcard());
        create.chain(query);
        Smb2CreateResponse createResp;
        try {
            createResp = th.send(create);
        }
        catch ( SmbException e ) {
            Smb2CreateResponse cr = create.getResponse();
            if ( cr != null && cr.isReceived() && cr.getStatus() == NtStatus.NT_STATUS_OK ) {
                try {
                    th.send(new Smb2CloseRequest(th.getConfig(), cr.getFileId()));
                }
                catch ( SmbException e2 ) {
                    e.addSuppressed(e2);
                }
            }

            Smb2QueryDirectoryResponse qr = query.getResponse();

            if ( qr != null && qr.isReceived() && qr.getStatus() == NtStatus.NT_STATUS_NO_SUCH_FILE ) {
                // this simply indicates an empty listing
                doClose();
                return null;
            }

            throw e;
        }
        this.fileId = createResp.getFileId();
        this.response = query.getResponse();
        FileEntry n = advance(false);
        if ( n == null ) {
            doClose();
        }
        return n;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.DirFileEntryEnumIteratorBase#fetchMore()
     */
    @SuppressWarnings ( "resource" )
    @Override
    protected boolean fetchMore () throws CIFSException {
        FileEntry[] results = this.response.getResults();
        SmbTreeHandleImpl th = getTreeHandle();
        Smb2QueryDirectoryRequest query = new Smb2QueryDirectoryRequest(th.getConfig(), this.fileId);
        query.setFileName(this.getWildcard());
        query.setFileIndex(results[ results.length - 1 ].getFileIndex());
        query.setQueryFlags(Smb2QueryDirectoryRequest.SMB2_INDEX_SPECIFIED);
        try {
            Smb2QueryDirectoryResponse r = th.send(query);
            if ( r.getStatus() == NtStatus.NT_STATUS_NO_MORE_FILES ) {
                return false;
            }
            this.response = r;
        }
        catch ( SmbException e ) {
            if ( e.getNtStatus() == NtStatus.NT_STATUS_NO_MORE_FILES ) {
                log.debug("End of listing", e);
                return false;
            }
            throw e;
        }
        return true;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.DirFileEntryEnumIteratorBase#isDone()
     */
    @Override
    protected boolean isDone () {
        return false;
    }


    /**
     * @throws CIFSException
     */
    @Override
    protected void doCloseInternal () throws CIFSException {
        try {
            @SuppressWarnings ( "resource" )
            SmbTreeHandleImpl th = getTreeHandle();
            if ( this.fileId != null && th.isConnected() ) {
                th.send(new Smb2CloseRequest(th.getConfig(), this.fileId));
            }
        }
        finally {
            this.fileId = null;
        }
    }

}
