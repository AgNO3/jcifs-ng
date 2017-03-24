/**
 * © 2017 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: Mar 24, 2017 by mbechler
 */
package jcifs.smb;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSException;
import jcifs.CloseableIterator;
import jcifs.ResourceNameFilter;
import jcifs.SmbConstants;
import jcifs.SmbResource;
import jcifs.SmbResourceLocator;

class NetServerEnumIterator implements CloseableIterator<FileEntry> {

    private static final Logger log = LoggerFactory.getLogger(NetServerEnumIterator.class);

    private final NetServerEnum2 request;
    private final NetServerEnum2Response response;
    private final SmbResource parent;
    private final SmbTreeHandleImpl treeHandle;
    private final ResourceNameFilter nameFilter;
    private final boolean workgroup;
    private int ridx;
    private FileEntry next;


    /**
     * @param parent
     * @param th
     * @param wildcard
     * @param searchAttributes
     * @param filter
     * @throws CIFSException
     * 
     */
    public NetServerEnumIterator ( SmbFile parent, SmbTreeHandleImpl th, String wildcard, int searchAttributes, ResourceNameFilter filter )
            throws CIFSException {
        this.parent = parent;
        this.nameFilter = filter;
        SmbResourceLocator locator = parent.getLocator();
        this.workgroup = locator.getType() == SmbConstants.TYPE_WORKGROUP;
        if ( locator.getURL().getHost().isEmpty() ) {
            this.request = new NetServerEnum2(th.getConfig(), th.getOEMDomainName(), NetServerEnum2.SV_TYPE_DOMAIN_ENUM);
            this.response = new NetServerEnum2Response(th.getConfig());
        }
        else if ( this.workgroup ) {
            this.request = new NetServerEnum2(th.getConfig(), locator.getURL().getHost(), NetServerEnum2.SV_TYPE_ALL);
            this.response = new NetServerEnum2Response(th.getConfig());
        }
        else {
            throw new SmbException("The requested list operations is invalid: " + locator.getURL().toString());
        }

        this.treeHandle = th.acquire();
        try {
            this.next = open();
        }
        catch ( Exception e ) {
            this.treeHandle.release();
            throw e;
        }

    }


    private FileEntry open () throws CIFSException {
        this.treeHandle.send(this.request, this.response);
        checkStatus();
        FileEntry n = advance();
        if ( n == null ) {
            doClose();
        }
        return n;
    }


    /**
     * @throws SmbException
     */
    private void checkStatus () throws SmbException {
        int status = this.response.status;
        if ( status != WinError.ERROR_SUCCESS && status != WinError.ERROR_MORE_DATA ) {
            throw new SmbException(status, true);
        }
    }


    private FileEntry advance () throws CIFSException {
        int n = this.response.status == WinError.ERROR_MORE_DATA ? this.response.numEntries - 1 : this.response.numEntries;
        while ( this.ridx < n ) {
            FileEntry itm = this.response.results[ this.ridx ];
            this.ridx++;
            if ( filter(itm) ) {
                return itm;
            }
        }

        if ( this.workgroup && this.response.status == WinError.ERROR_MORE_DATA ) {
            this.request.reset(0, this.response.lastName);
            this.response.reset();
            this.request.subCommand = (byte) SmbComTransaction.NET_SERVER_ENUM3;
            this.treeHandle.send(this.request, this.response);
            checkStatus();
            this.ridx = 0;
            return advance();
        }
        return null;
    }


    private final boolean filter ( FileEntry fe ) {
        String name = fe.getName();
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
     * @see jcifs.CloseableIterator#close()
     */
    @Override
    public void close () throws CIFSException {
        if ( this.next != null ) {
            doClose();
        }
    }


    /**
     * 
     */
    private void doClose () {
        this.treeHandle.release();
        this.next = null;
    }

}