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
package jcifs.smb;


import javax.security.auth.Subject;

import jcifs.CIFSContext;


/**
 * @author mbechler
 *
 */
public interface SmbCredentials extends Cloneable {

    /**
     * @return the domain the user account is in
     */
    String getUserDomain ();


    /**
     * @return whether these are anonymous credentials
     */
    boolean isAnonymous ();


    /**
     * @return whether these are guest credentials
     */
    boolean isGuest ();


    /**
     * 
     * @return a copy of the credentials
     */
    SmbCredentials clone ();


    /**
     * @param transportContext
     * @param host
     * @param initialToken
     * @param doSigning
     * @return a new context
     * @throws SmbException
     */
    SSPContext createContext ( CIFSContext transportContext, String host, byte[] initialToken, boolean doSigning ) throws SmbException;


    /**
     * @return subject associated with the credentials
     */
    Subject getSubject ();
}
