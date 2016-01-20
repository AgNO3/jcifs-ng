/**
 * © 2016 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 17.01.2016 by mbechler
 */
package jcifs.context;


import java.net.URLStreamHandler;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.SmbTransportPool;
import jcifs.netbios.NameServiceClient;
import jcifs.smb.BufferCache;
import jcifs.smb.Dfs;
import jcifs.smb.Handler;
import jcifs.smb.SmbCredentials;


/**
 * @author mbechler
 *
 */
public class CIFSContextWrapper implements CIFSContext {

    private final CIFSContext delegate;


    /**
     * 
     */
    public CIFSContextWrapper ( CIFSContext delegate ) {
        this.delegate = delegate;
    }


    /**
     * @param withCredentials
     * @return
     */
    protected CIFSContext wrap ( CIFSContext newContext ) {
        return newContext;
    }


    @Override
    public Configuration getConfig () {
        return this.delegate.getConfig();
    }


    @Override
    public Dfs getDfs () {
        return this.delegate.getDfs();
    }


    @Override
    public SmbCredentials getCredentials () {
        return this.delegate.getCredentials();
    }

    private Handler handler;


    /**
     * {@inheritDoc}
     *
     * @see jcifs.context.CIFSContextWrapper#getUrlHandler()
     */
    @Override
    public URLStreamHandler getUrlHandler () {
        if ( this.handler == null ) {
            this.handler = new Handler(this);
        }
        return this.handler;
    }


    @Override
    public boolean hasDefaultCredentials () {
        return this.delegate.hasDefaultCredentials();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.CIFSContext#withCredentials(jcifs.smb.SmbCredentials)
     */
    @Override
    public CIFSContext withCredentials ( SmbCredentials creds ) {
        return wrap(this.delegate.withCredentials(creds));
    }


    @Override
    public CIFSContext withDefaultCredentials () {
        return wrap(this.delegate.withDefaultCredentials());
    }


    @Override
    public CIFSContext withAnonymousCredentials ( boolean nullCreds ) {
        return wrap(this.delegate.withAnonymousCredentials(nullCreds));
    }


    @Override
    public CIFSContext withGuestCrendentials () {
        return wrap(this.delegate.withGuestCrendentials());
    }


    @Override
    public boolean renewCredentials ( String locationHint, Throwable error ) {
        return this.delegate.renewCredentials(locationHint, error);
    }


    @Override
    public NameServiceClient getNameServiceClient () {
        return this.delegate.getNameServiceClient();
    }


    @Override
    public BufferCache getBufferCache () {
        return this.delegate.getBufferCache();
    }


    @Override
    public SmbTransportPool getTransportPool () {
        return this.delegate.getTransportPool();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.CIFSContext#close()
     */
    @Override
    public void close () throws CIFSException {
        this.delegate.close();
    }
}
