/**
 * © 2016 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 17.01.2016 by mbechler
 */
package jcifs;


import java.net.InetAddress;
import java.net.UnknownHostException;

import jcifs.smb.NtlmChallenge;
import jcifs.smb.SmbException;
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
    SmbTransport getSmbTransport ( CIFSContext tc, UniAddress address, int port, boolean nonPooled );


    /**
     * @param tc
     * @param address
     * @param port
     * @param localAddr
     * @param localPort
     * @param hostName
     * @return
     */
    SmbTransport getSmbTransport ( CIFSContext tc, UniAddress address, int port, InetAddress localAddr, int localPort, String hostName,
            boolean nonPooled );


    /**
     * @param trans
     */
    void removeTransport ( SmbTransport trans );


    /**
     * 
     */
    void close () throws CIFSException;


    /**
     * @param dc
     * @param transportContext
     */
    void logon ( UniAddress dc, CIFSContext transportContext ) throws SmbException;


    /**
     * @param dc
     * @param transportContext
     * @return
     */
    byte[] getChallenge ( UniAddress dc, CIFSContext transportContext ) throws SmbException;


    /**
     * @param transportContext
     * @param defaultDomain
     * @return
     */
    NtlmChallenge getChallengeForDomain ( CIFSContext transportContext, String defaultDomain ) throws SmbException, UnknownHostException;

}