/**
 * © 2016 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 17.01.2016 by mbechler
 */
package jcifs;


/**
 * @author mbechler
 *
 */
public class RuntimeCIFSException extends RuntimeException {

    /**
     * 
     */
    private static final long serialVersionUID = -2611196678846438579L;


    public RuntimeCIFSException () {
        super();
    }


    public RuntimeCIFSException ( String message, Throwable cause ) {
        super(message, cause);
    }


    public RuntimeCIFSException ( String message ) {
        super(message);
    }


    public RuntimeCIFSException ( Throwable cause ) {
        super(cause);
    }

}
