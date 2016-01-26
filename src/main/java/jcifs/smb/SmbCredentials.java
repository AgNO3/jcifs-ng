package jcifs.smb;
/**
 * © 2016 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 16.01.2016 by mbechler
 */


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


    SmbCredentials clone ();


    /**
     * @param transportContext
     */
    SSPContext createContext ( CIFSContext transportContext, String host, byte[] initialToken, boolean doSigning ) throws SmbException;


    /**
     * @return
     */
    boolean isNull ();


    /**
     * @return
     */
    boolean isGuest ();


    /**
     * 
     */
    Subject getSubject ();
}
