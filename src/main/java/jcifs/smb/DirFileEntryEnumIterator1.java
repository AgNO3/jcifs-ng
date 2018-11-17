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
import jcifs.SmbResourceLocator;
import jcifs.internal.smb1.com.SmbComBlankResponse;
import jcifs.internal.smb1.com.SmbComFindClose2;
import jcifs.internal.smb1.trans.SmbComTransaction;
import jcifs.internal.smb1.trans2.Trans2FindFirst2;
import jcifs.internal.smb1.trans2.Trans2FindFirst2Response;
import jcifs.internal.smb1.trans2.Trans2FindNext2;


class DirFileEntryEnumIterator1 extends DirFileEntryEnumIteratorBase {

    private static final Logger log = LoggerFactory.getLogger(DirFileEntryEnumIterator1.class);

    private Trans2FindNext2 nextRequest;
    private Trans2FindFirst2Response response;


    public DirFileEntryEnumIterator1 ( SmbTreeHandleImpl th, SmbResource parent, String wildcard, ResourceNameFilter filter, int searchAttributes )
            throws CIFSException {
        super(th, parent, wildcard, filter, searchAttributes);
    }


    @SuppressWarnings ( "resource" )
    @Override
    protected final FileEntry open () throws CIFSException {
        SmbResourceLocator loc = this.getParent().getLocator();
        String unc = loc.getUNCPath();
        String p = loc.getURL().getPath();
        if ( p.lastIndexOf('/') != ( p.length() - 1 ) ) {
            throw new SmbException(loc.getURL() + " directory must end with '/'");
        }
        if ( unc.lastIndexOf('\\') != ( unc.length() - 1 ) ) {
            throw new SmbException(unc + " UNC must end with '\\'");
        }

        SmbTreeHandleImpl th = getTreeHandle();
        this.response = new Trans2FindFirst2Response(th.getConfig());

        try {
            th.send(
                new Trans2FindFirst2(
                    th.getConfig(),
                    unc,
                    this.getWildcard(),
                    this.getSearchAttributes(),
                    th.getConfig().getListCount(),
                    th.getConfig().getListSize()),
                this.response);

            this.nextRequest = new Trans2FindNext2(
                th.getConfig(),
                this.response.getSid(),
                this.response.getResumeKey(),
                this.response.getLastName(),
                th.getConfig().getListCount(),
                th.getConfig().getListSize());
        }
        catch ( SmbException e ) {
            if ( this.response != null && this.response.isReceived() && e.getNtStatus() == NtStatus.NT_STATUS_NO_SUCH_FILE ) {
                doClose();
                return null;
            }
            throw e;
        }

        this.response.setSubCommand(SmbComTransaction.TRANS2_FIND_NEXT2);
        FileEntry n = advance(false);
        if ( n == null ) {
            doClose();
        }
        return n;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.DirFileEntryEnumIteratorBase#getResults()
     */
    @Override
    protected FileEntry[] getResults () {
        return this.response.getResults();
    }


    /**
     * {@inheritDoc}
     * 
     * @throws CIFSException
     *
     * @see jcifs.smb.DirFileEntryEnumIteratorBase#fetchMore()
     */
    @Override
    protected boolean fetchMore () throws CIFSException {
        this.nextRequest.reset(this.response.getResumeKey(), this.response.getLastName());
        this.response.reset();
        try {
            getTreeHandle().send(this.nextRequest, this.response);
            return this.response.getStatus() != NtStatus.NT_STATUS_NO_MORE_FILES;
        }
        catch ( SmbException e ) {
            if ( e.getNtStatus() == NtStatus.NT_STATUS_NO_MORE_FILES ) {
                log.debug("No more entries", e);
                return false;
            }
            throw e;
        }
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.DirFileEntryEnumIteratorBase#isDone()
     */
    @Override
    protected boolean isDone () {
        return this.response.isEndOfSearch();
    }


    /**
     * @throws CIFSException
     */
    @Override
    protected void doCloseInternal () throws CIFSException {
        try {
            @SuppressWarnings ( "resource" )
            SmbTreeHandleImpl th = getTreeHandle();
            if ( this.response != null ) {
                th.send(new SmbComFindClose2(th.getConfig(), this.response.getSid()), new SmbComBlankResponse(th.getConfig()));
            }
        }
        catch ( SmbException se ) {
            log.debug("SmbComFindClose2 failed", se);
        }

    }

}