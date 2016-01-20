/**
 * © 2016 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 17.01.2016 by mbechler
 */
package jcifs.context;


import org.apache.log4j.Logger;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbCredentials;


/**
 * @author mbechler
 *
 */
public abstract class AbstractCIFSContext extends Thread implements CIFSContext {

    private static final Logger log = Logger.getLogger(AbstractCIFSContext.class);
    private boolean closed;


    /**
     * 
     */
    public AbstractCIFSContext () {
        Runtime.getRuntime().addShutdownHook(this);
    }


    /**
     * @param creds
     * @return a wrapped context with the given credentials
     */
    @Override
    public CIFSContext withCredentials ( SmbCredentials creds ) {
        return new CIFSContextCredentialWrapper(this, creds);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.CIFSContext#withAnonymousCredentials(boolean)
     */
    @Override
    public CIFSContext withAnonymousCredentials ( boolean nullCreds ) {
        return withCredentials(new NtlmPasswordAuthentication(this, nullCreds));
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.CIFSContext#withDefaultCredentials()
     */
    @Override
    public CIFSContext withDefaultCredentials () {
        return withCredentials(getDefaultCredentials());
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.CIFSContext#withGuestCrendentials()
     */
    @Override
    public CIFSContext withGuestCrendentials () {
        return withCredentials(new NtlmPasswordAuthentication(this, null, "GUEST", ""));
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.CIFSContext#getCredentials()
     */
    @Override
    public SmbCredentials getCredentials () {
        return this.getDefaultCredentials();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.CIFSContext#hasDefaultCredentials()
     */
    @Override
    public boolean hasDefaultCredentials () {
        return this.getDefaultCredentials() != null && !this.getDefaultCredentials().isAnonymous();
    }


    /**
     * @return
     */
    protected abstract SmbCredentials getDefaultCredentials ();


    /**
     * {@inheritDoc}
     *
     * @see jcifs.CIFSContext#renewCredentials(java.lang.String, java.lang.Throwable)
     */
    @Override
    public boolean renewCredentials ( String locationHint, Throwable error ) {
        return false;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.CIFSContext#close()
     */
    @Override
    public void close () throws CIFSException {
        if ( !this.closed ) {
            Runtime.getRuntime().removeShutdownHook(this);
        }
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Thread#run()
     */
    @Override
    public void run () {
        try {
            this.closed = true;
            close();
        }
        catch ( CIFSException e ) {
            log.warn("Failed to close context on shutdown", e);
        }
    }
}
