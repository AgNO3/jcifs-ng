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


import java.net.MalformedURLException;
import java.net.URLStreamHandler;

import jcifs.BufferCache;
import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.Credentials;
import jcifs.DfsResolver;
import jcifs.NameServiceClient;
import jcifs.SidResolver;
import jcifs.SmbPipeResource;
import jcifs.SmbResource;
import jcifs.SmbTransportPool;
import jcifs.smb.Handler;
import jcifs.smb.SmbFile;
import jcifs.smb.SmbNamedPipe;


/**
 * @author mbechler
 *
 */
public class CIFSContextWrapper implements CIFSContext {

    private final CIFSContext delegate;
    private Handler wrappedHandler;


    /**
     * @param delegate
     *            context to delegate non-override methods to
     * 
     */
    public CIFSContextWrapper ( CIFSContext delegate ) {
        this.delegate = delegate;
    }


    /**
     * {@inheritDoc}
     * 
     * @throws CIFSException
     * 
     * @see jcifs.CIFSContext#get(java.lang.String)
     */
    @Override
    public SmbResource get ( String url ) throws CIFSException {
        try {
            return new SmbFile(url, this);
        }
        catch ( MalformedURLException e ) {
            throw new CIFSException("Invalid URL " + url, e);
        }
    }


    /**
     * 
     * {@inheritDoc}
     *
     * @see jcifs.CIFSContext#getPipe(java.lang.String, int)
     */
    @Override
    public SmbPipeResource getPipe ( String url, int pipeType ) throws CIFSException {
        try {
            return new SmbNamedPipe(url, pipeType, this);
        }
        catch ( MalformedURLException e ) {
            throw new CIFSException("Invalid URL " + url, e);
        }
    }


    protected CIFSContext wrap ( CIFSContext newContext ) {
        return newContext;
    }


    @Override
    public Configuration getConfig () {
        return this.delegate.getConfig();
    }


    @Override
    public DfsResolver getDfs () {
        return this.delegate.getDfs();
    }


    @Override
    public Credentials getCredentials () {
        return this.delegate.getCredentials();
    }


    @Override
    public URLStreamHandler getUrlHandler () {
        if ( this.wrappedHandler == null ) {
            this.wrappedHandler = new Handler(this);
        }
        return this.wrappedHandler;
    }


    @Override
    public SidResolver getSIDResolver () {
        return this.delegate.getSIDResolver();
    }


    @Override
    public boolean hasDefaultCredentials () {
        return this.delegate.hasDefaultCredentials();
    }


    @Override
    public CIFSContext withCredentials ( Credentials creds ) {
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


    @Override
    public boolean close () throws CIFSException {
        return this.delegate.close();
    }
}
