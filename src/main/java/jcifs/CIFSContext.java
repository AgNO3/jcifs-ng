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
     * 
     * @return the configuration
     */
    Configuration getConfig ();


    /**
     * @return
     */
    Dfs getDfs ();


    /**
     * 
     * @return
     */
    SmbCredentials getCredentials ();


    /**
     * @return
     */
    URLStreamHandler getUrlHandler ();


    /**
     * @return
     */
    boolean hasDefaultCredentials ();


    /**
     * @return
     */
    CIFSContext withDefaultCredentials ();


    /**
     * @return
     */
    CIFSContext withAnonymousCredentials ( boolean nullCreds );


    /**
     * 
     * @return
     */
    CIFSContext withGuestCrendentials ();


    /**
     * 
     * @param creds
     * @return
     */
    CIFSContext withCredentials ( SmbCredentials creds );


    /**
     * @param locationHint
     * @param error
     * @return whether new credentials are obtained
     */
    boolean renewCredentials ( String locationHint, Throwable error );


    /**
     * @return
     */
    NameServiceClient getNameServiceClient ();


    /**
     * @return
     */
    BufferCache getBufferCache ();


    /**
     * @return
     */
    SmbTransportPool getTransportPool ();

}
