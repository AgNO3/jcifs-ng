/**
 * © 2016 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 17.01.2016 by mbechler
 */
package jcifs;


import java.net.InetAddress;

import jcifs.smb.SmbTransport;


/**
 * @author mbechler
 *
 */
public interface SmbTransportPool {

    /**
     * @param tc
     * @param address
     * @param port
     * @return
     */
    SmbTransport getSmbTransport ( CIFSContext tc, UniAddress address, int port );


    /**
     * @param tc
     * @param address
     * @param port
     * @param localAddr
     * @param localPort
     * @param hostName
     * @return
     */
    SmbTransport getSmbTransport ( CIFSContext tc, UniAddress address, int port, InetAddress localAddr, int localPort, String hostName );


    /**
     * @param trans
     */
    void removeTransport ( SmbTransport trans );


    /**
     * 
     */
    void close () throws CIFSException;

}