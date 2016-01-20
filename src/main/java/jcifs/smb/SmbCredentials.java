package jcifs.smb;
/**
 * © 2016 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 16.01.2016 by mbechler
 */


import java.security.GeneralSecurityException;


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
     * @param smbSession
     * @param andx
     * @param andxResponse
     */
    void sessionSetup ( SmbSession smbSession, ServerMessageBlock andx, ServerMessageBlock andxResponse )
            throws SmbException, GeneralSecurityException;


    /**
     * @return whether these are anonymous credentials
     */
    boolean isAnonymous ();


    SmbCredentials clone ();


    byte[] getSessionKey ();
}
