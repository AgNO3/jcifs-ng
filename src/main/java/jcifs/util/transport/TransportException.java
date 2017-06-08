/*
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
package jcifs.util.transport;


import jcifs.CIFSException;


/**
 *
 */
public class TransportException extends CIFSException {

    /**
     * 
     */
    private static final long serialVersionUID = 3743631204022885618L;


    /**
     * 
     */
    public TransportException () {}


    /**
     * 
     * @param msg
     */
    public TransportException ( String msg ) {
        super(msg);
    }


    /**
     * 
     * @param rootCause
     */
    public TransportException ( Throwable rootCause ) {
        super(rootCause);
    }


    /**
     * 
     * @param msg
     * @param rootCause
     */
    public TransportException ( String msg, Throwable rootCause ) {
        super(msg, rootCause);
    }


    /**
     * 
     * @return root cause
     */
    @Deprecated
    public Throwable getRootCause () {
        return getCause();
    }
}
