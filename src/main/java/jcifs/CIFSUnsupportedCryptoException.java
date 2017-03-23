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


/**
 * Runtime exception indicating that the JDK does not support the cryptographic primitives that we use.
 * 
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
