/**
 * © 2016 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 15.01.2016 by mbechler
 */
package jcifs;


import java.net.URLStreamHandler;

import jcifs.netbios.NameServiceClient;
import jcifs.smb.BufferCache;
import jcifs.smb.Dfs;
import jcifs.smb.SmbCredentials;


/**
 * @author mbechler
 *
 */
public interface CIFSContext {

    /**
     * 
     * @throws CIFSException
     */
    void close () throws CIFSException;


    /**
     * @return the name server client
     */
    NameServiceClient getNameServiceClient ();


    /**
     * @return the buffer cache
     */
    BufferCache getBufferCache ();


    /**
     * @return the transport pool
     */
    SmbTransportPool getTransportPool ();


    /**
     * 
     * @return the active configuration
     */
    Configuration getConfig ();


    /**
     * @return the DFS instance
     */
    Dfs getDfs ();


    /**
     * @return
     */
    SidResolver getSIDResolver ();


    /**
     * 
     * @return the used credentials
     */
    SmbCredentials getCredentials ();


    /**
     * @return an URL handler using this context
     */
    URLStreamHandler getUrlHandler ();


    /**
     * @return whether default credentials are available
     */
    boolean hasDefaultCredentials ();


    /**
     * @return a child context using the default credentials
     */
    CIFSContext withDefaultCredentials ();


    /**
     * @param nullCreds
     * @return a child context using anonymous credentials
     */
    CIFSContext withAnonymousCredentials ( boolean nullCreds );


    /**
     * 
     * @return a child context using guest credentials
     */
    CIFSContext withGuestCrendentials ();


    /**
     * 
     * @param creds
     * @return a child using using the given credentials
     */
    CIFSContext withCredentials ( SmbCredentials creds );


    /**
     * @param locationHint
     * @param error
     * @return whether new credentials are obtained
     */
    boolean renewCredentials ( String locationHint, Throwable error );

}
