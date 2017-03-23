/*
 * © 2017 AgNO3 Gmbh & Co. KG
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


/**
 * Interface for both netbios and internet addresses
 * 
 * @author mbechler
 *
 */
public interface Address {

    /**
     * 
     * @param type
     * @return instance for type, null if the type cannot be unwrapped
     */
    <T extends Address> T unwrap ( Class<T> type );


    /**
     * 
     * @return the resolved host name, or the host address if it could not be resolved
     */
    String getHostName ();


    /**
     * Return the IP address as text such as "192.168.1.15".
     * 
     * @return the ip address
     */
    String getHostAddress ();


    /**
     * 
     * @return this address as an InetAddress
     * @throws UnknownHostException
     */
    InetAddress toInetAddress () throws UnknownHostException;


    /**
     * Guess called name to try for session establishment. These
     * methods are used by the smb package.
     * 
     * @param tc
     * 
     * @return guessed name
     */
    String firstCalledName ();


    /**
     * Guess next called name to try for session establishment. These
     * methods are used by the smb package.
     * 
     * @param tc
     * 
     * @return guessed name
     */
    String nextCalledName ( CIFSContext tc );

}
