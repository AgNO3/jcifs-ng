/**
 * © 2017 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: Mar 24, 2017 by mbechler
 */
package jcifs.smb;

import java.net.MalformedURLException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSException;
import jcifs.CloseableIterator;
import jcifs.ResourceFilter;
import jcifs.SmbResource;

abstract class FileEntryAdapterIterator implements CloseableIterator<SmbResource> {

    private static final Logger log = LoggerFactory.getLogger(FileEntryAdapterIterator.class);

    private final CloseableIterator<FileEntry> delegate;
    private final ResourceFilter filter;
    private final SmbResource parent;
    private SmbResource next;


    /**
     * @param parent
     * @param delegate
     * @param filter
     * 
     */
    public FileEntryAdapterIterator ( SmbResource parent, CloseableIterator<FileEntry> delegate, ResourceFilter filter ) {
        this.parent = parent;
        this.delegate = delegate;
        this.filter = filter;
        this.next = advance();
    }


    /**
     * @return the parent
     */
    protected final SmbResource getParent () {
        return this.parent;
    }


    /**
     * @return
     * 
     */
    private SmbResource advance () {
        while ( this.delegate.hasNext() ) {
            FileEntry fe = this.delegate.next();
            if ( this.filter == null ) {
                try {
                    return adapt(fe);
                }
                catch ( MalformedURLException e ) {
                    log.error("Failed to create child URL", e);
                    continue;
                }
            }

            try ( SmbResource r = adapt(fe) ) {
                if ( this.filter.accept(r) ) {
                    return r;
                }
            }
            catch ( MalformedURLException e ) {
                log.error("Failed to create child URL", e);
                continue;
            }
            catch ( CIFSException e ) {
                log.error("Filter failed", e);
                continue;
            }
        }
        return null;
    }


    protected abstract SmbResource adapt ( FileEntry e ) throws MalformedURLException;


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
     * @throws CIFSException
     *
     * @see java.lang.AutoCloseable#close()
     */
    @Override
    public void close () throws CIFSException {
        this.delegate.close();
    }

}