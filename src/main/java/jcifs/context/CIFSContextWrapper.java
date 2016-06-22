/*
 * © 2016 AgNO3 Gmbh & Co. KG
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
package jcifs.context;


import java.net.URLStreamHandler;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.SidResolver;
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
    private Handler wrappedHandler;


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


    /**
     * {@inheritDoc}
     *
     * @see jcifs.context.CIFSContextWrapper#getUrlHandler()
     */
    @Override
    public URLStreamHandler getUrlHandler () {
        if ( this.wrappedHandler == null ) {
            this.wrappedHandler = new Handler(this);
        }
        return this.wrappedHandler;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.CIFSContext#getSIDResolver()
     */
    @Override
    public SidResolver getSIDResolver () {
        return this.delegate.getSIDResolver();
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
    public CIFSContext withAnonymousCredentials () {
        return wrap(this.delegate.withAnonymousCredentials());
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
