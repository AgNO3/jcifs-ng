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