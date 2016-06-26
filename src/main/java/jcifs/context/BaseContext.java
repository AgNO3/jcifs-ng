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

import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.SidResolver;
import jcifs.SmbTransportPool;
import jcifs.netbios.NameServiceClient;
import jcifs.smb.BufferCache;
import jcifs.smb.Dfs;
import jcifs.smb.Handler;
import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SIDCacheImpl;
import jcifs.smb.SmbCredentials;
import jcifs.smb.SmbTransportPoolImpl;


/**
 * @author mbechler
 *
 */
public class BaseContext extends AbstractCIFSContext {

    private final Configuration config;
    private final Dfs dfs;
    private final SidResolver sidResolver;
    private final Handler urlHandler;
    private final NameServiceClient nameServiceClient;
    private final BufferCache bufferCache;
    private final SmbTransportPool transportPool;
    private final SmbCredentials defaultCredentials;


    /**
     * Construct a context
     * 
     * @param config
     *            configuration for the context
     * 
     */
    public BaseContext ( Configuration config ) {
        this.config = config;
        this.dfs = new Dfs(this);
        this.sidResolver = new SIDCacheImpl(this);
        this.urlHandler = new Handler(this);
        this.nameServiceClient = new NameServiceClient(this);
        this.bufferCache = new BufferCache(this.config);
        this.transportPool = new SmbTransportPoolImpl();
        this.defaultCredentials = new NtlmPasswordAuthentication(this, null, null, null);
    }


    @Override
    public SmbTransportPool getTransportPool () {
        return this.transportPool;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.CIFSContext#getConfig()
     */
    @Override
    public Configuration getConfig () {
        return this.config;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.CIFSContext#getDfs()
     */
    @Override
    public Dfs getDfs () {
        return this.dfs;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.CIFSContext#getNameServiceClient()
     */
    @Override
    public NameServiceClient getNameServiceClient () {
        return this.nameServiceClient;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.CIFSContext#getBufferCache()
     */
    @Override
    public BufferCache getBufferCache () {
        return this.bufferCache;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.CIFSContext#getUrlHandler()
     */
    @Override
    public URLStreamHandler getUrlHandler () {
        return this.urlHandler;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.CIFSContext#getSIDResolver()
     */
    @Override
    public SidResolver getSIDResolver () {
        return this.sidResolver;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.context.AbstractCIFSContext#getDefaultCredentials()
     */
    @Override
    protected SmbCredentials getDefaultCredentials () {
        return this.defaultCredentials;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.CIFSContext#close()
     */
    @Override
    public void close () throws CIFSException {
        super.close();
        this.transportPool.close();
    }

}
