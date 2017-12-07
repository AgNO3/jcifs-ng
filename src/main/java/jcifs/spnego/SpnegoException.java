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
package jcifs.spnego;


import jcifs.CIFSException;


/**
 * @author mbechler
 *
 */
public class SpnegoException extends CIFSException {

    /**
     * 
     */
    private static final long serialVersionUID = -4591854684249021395L;


    /**
     * 
     */
    public SpnegoException () {
        super();
    }


    /**
     * @param message
     * @param cause
     */
    public SpnegoException ( String message, Throwable cause ) {
        super(message, cause);
    }


    /**
     * @param message
     */
    public SpnegoException ( String message ) {
        super(message);
    }


    /**
     * @param cause
     */
    public SpnegoException ( Throwable cause ) {
        super(cause);
    }

}
