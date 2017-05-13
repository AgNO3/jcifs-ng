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


import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSException;
import jcifs.FileNotifyInformation;
import jcifs.SmbConstants;
import jcifs.SmbWatchHandle;
import jcifs.internal.smb1.trans.nt.NtTransNotifyChange;
import jcifs.internal.smb1.trans.nt.NtTransNotifyChangeResponse;


/**
 * @author mbechler
 *
 */
class SmbWatchHandleImpl implements SmbWatchHandle {

    private static final Logger log = LoggerFactory.getLogger(SmbWatchHandleImpl.class);

    private final SmbFileHandleImpl handle;
    private final int filter;
    private final boolean recursive;


    /**
     * @param fh
     * @param filter
     * @param recursive
     * 
     */
    public SmbWatchHandleImpl ( SmbFileHandleImpl fh, int filter, boolean recursive ) {
        this.handle = fh;
        this.filter = filter;
        this.recursive = recursive;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.SmbWatchHandle#watch()
     */
    @Override
    public List<FileNotifyInformation> watch () throws CIFSException {
        if ( !this.handle.isValid() ) {
            throw new SmbException("Watch was broken by tree disconnect");
        }
        try ( SmbTreeHandleImpl th = this.handle.getTree() ) {

            if ( !th.hasCapability(SmbConstants.CAP_NT_SMBS) ) {
                throw new SmbUnsupportedOperationException("Not supported without CAP_NT_SMBS");
            }

            /*
             * NtTrans Notify Change Request / Response
             */
            NtTransNotifyChange request = new NtTransNotifyChange(th.getConfig(), this.handle.getFid(), this.filter, this.recursive);
            NtTransNotifyChangeResponse response = new NtTransNotifyChangeResponse(th.getConfig());

            if ( log.isTraceEnabled() ) {
                log.trace("Sending NtTransNotifyChange for " + this.handle);
            }
            th.send(request, response, RequestParam.NO_TIMEOUT, RequestParam.NO_RETRY);
            if ( log.isTraceEnabled() ) {
                log.trace("Returned from NtTransNotifyChange " + response.getStatus());
            }
            if ( response.getStatus() == 0x0000010B ) {
                this.handle.markClosed();
            }
            if ( response.getStatus() == 0x0000010C ) {
                response.getNotifyInformation().clear();
            }
            return response.getNotifyInformation();
        }
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.SmbWatchHandle#call()
     */
    @Override
    public List<FileNotifyInformation> call () throws CIFSException {
        return watch();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.SmbWatchHandle#close()
     */
    @Override
    public void close () throws CIFSException {
        if ( this.handle.isValid() ) {
            this.handle.close(0L);
        }
    }
}
