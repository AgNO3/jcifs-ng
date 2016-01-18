/**
 * © 2016 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 17.01.2016 by mbechler
 */
package jcifs;


import java.io.IOException;


/**
 * @author mbechler
 *
 */
public class CIFSException extends IOException {

    /**
     * 
     */
    private static final long serialVersionUID = 7806460518865806784L;


    public CIFSException () {
        super();
    }


    public CIFSException ( String message, Throwable cause ) {
        super(message, cause);
    }


    public CIFSException ( String message ) {
        super(message);
    }


    public CIFSException ( Throwable cause ) {
        super(cause);
    }

}
