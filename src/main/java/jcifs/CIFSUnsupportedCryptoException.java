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
public class CIFSUnsupportedCryptoException extends RuntimeCIFSException {

    /**
     * 
     */
    private static final long serialVersionUID = -6350312430383107348L;


    /**
     * 
     */
    public CIFSUnsupportedCryptoException () {}


    /**
     * @param message
     * @param cause
     */
    public CIFSUnsupportedCryptoException ( String message, Throwable cause ) {
        super(message, cause);
    }


    /**
     * @param message
     */
    public CIFSUnsupportedCryptoException ( String message ) {
        super(message);
    }


    /**
     * @param cause
     */
    public CIFSUnsupportedCryptoException ( Throwable cause ) {
        super(cause);
    }

}
