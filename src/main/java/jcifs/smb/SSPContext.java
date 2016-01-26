/**
 * © 2016 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 26.01.2016 by mbechler
 */
package jcifs.smb;


import org.ietf.jgss.Oid;


/**
 * @author mbechler
 *
 */
public interface SSPContext {

    /**
     * @return
     */
    byte[] getSigningKey () throws SmbException;


    /**
     * @return
     */
    boolean isEstablished ();


    /**
     * @param token
     * @param i
     * @param j
     * @return
     */
    byte[] initSecContext ( byte[] token, int off, int len ) throws SmbException;


    /**
     * @return
     */
    String getNetbiosName ();


    /**
     * @throws SmbException
     */
    void dispose () throws SmbException;


    /**
     * @param mechanism
     */
    boolean isSupported ( Oid mechanism );


    /**
     * @return
     */
    int getFlags ();


    /**
     * @return
     */
    Oid[] getSupportedMechs ();

}
