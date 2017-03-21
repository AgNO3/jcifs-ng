/**
 * © 2017 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 20.03.2017 by mbechler
 */
package jcifs.smb;


/**
 * @author mbechler
 *
 */
public enum RequestParam {

    /**
     * 
     */
    NONE,

    /**
     * Wait indefinitely for a response
     */
    NO_TIMEOUT,

    /**
     * Do not retry request on failure
     */
    NO_RETRY
}
