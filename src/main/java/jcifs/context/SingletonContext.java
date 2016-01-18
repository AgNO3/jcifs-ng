/**
 * © 2016 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 17.01.2016 by mbechler
 */
package jcifs.context;


import java.net.URLStreamHandler;

import org.apache.log4j.Logger;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.SmbTransportPool;
import jcifs.config.BaseConfiguration;
import jcifs.config.PropertyConfiguration;
import jcifs.netbios.NameServiceClient;
import jcifs.smb.BufferCache;
import jcifs.smb.Dfs;
import jcifs.smb.Handler;
import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbCredentials;
import jcifs.smb.SmbTransportPoolImpl;


/**
 * @author mbechler
 *
 */
public class SingletonContext extends AbstractCIFSContext implements CIFSContext {

    private static final Logger log = Logger.getLogger(SingletonContext.class);
    private static SingletonContext INSTANCE;


    public static final SingletonContext getInstance () {
        if ( INSTANCE == null ) {
            try {
                log.debug("Initializing singleton context");
                INSTANCE = new SingletonContext();
            }
            catch ( CIFSException e ) {
                log.error("Failed to create singleton JCIFS context", e);
            }
        }

        return INSTANCE;
    }

    private final BaseConfiguration config;
    private final Dfs dfs;
    private final Handler urlHandler;
    private final NameServiceClient nameServiceClient;
    private final BufferCache bufferCache;
    private final SmbTransportPool transportPool;
    private final SmbCredentials defaultCredentials;


    /**
     * 
     */
    private SingletonContext () throws CIFSException {
        this.config = new PropertyConfiguration(System.getProperties());
        this.dfs = new Dfs(this);
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
