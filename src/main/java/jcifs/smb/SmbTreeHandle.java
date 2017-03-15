/**
 * © 2017 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 14.03.2017 by mbechler
 */
package jcifs.smb;


import jcifs.Configuration;


/**
 * @author mbechler
 *
 */
public interface SmbTreeHandle extends AutoCloseable {

    /**
     * 
     * @throws SmbException
     */
    void ensureDFSResolved () throws SmbException;


    /**
     * @param cap
     * @return whether the capabiltiy is present
     * @throws SmbException
     */
    boolean hasCapability ( int cap ) throws SmbException;


    /**
     * @return the tree is connected
     */
    boolean isConnected ();


    /**
     * @return the active configuration
     */
    Configuration getConfig ();


    /**
     * {@inheritDoc}
     *
     * @see java.lang.AutoCloseable#close()
     */
    @Override
    void close () throws SmbException;


    /**
     * 
     */
    void release ();


    /**
     * @return server timezone offset
     */
    long getServerTimeZoneOffset ();


    /**
     * @return server reported domain name
     */
    String getOEMDomainName ();


    /**
     * @return the service we are connected to
     */
    String getConnectedService ();


    /**
     * @return the share we are connected to
     */
    String getConnectedShare ();


    /**
     * @param th
     * @return whether the handles refer to the same tree
     */
    boolean isSameTree ( SmbTreeHandleImpl th );


    /**
     * @return the send buffer size of the underlying connection
     */
    int getSendBufferSize ();


    /**
     * @return the receive buffer size of the underlying connection
     */
    int getReceiveBufferSize ();


    /**
     * @return the maximum buffer size reported by the server
     */
    int getMaximumBufferSize ();


    /**
     * @return whether the session uses SMB signing
     */
    boolean areSignaturesActive ();

}