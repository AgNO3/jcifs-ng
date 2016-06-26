/* jcifs msrpc client library in Java
 * Copyright (C) 2006  "Michael B. Allen" <jcifs at samba dot org>
 *                     "Eric Glass" <jcifs at samba dot org>
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

package jcifs.dcerpc;


import jcifs.CIFSException;
import jcifs.smb.WinError;
import jcifs.util.Hexdump;


/**
 *
 */
public class DcerpcException extends CIFSException implements DcerpcError, WinError {

    /**
     * 
     */
    private static final long serialVersionUID = -6113895861333916945L;


    static String getMessageByDcerpcError ( int errcode ) {
        int min = 0;
        int max = DCERPC_FAULT_CODES.length;

        while ( max >= min ) {
            int mid = ( min + max ) / 2;

            if ( errcode > DCERPC_FAULT_CODES[ mid ] ) {
                min = mid + 1;
            }
            else if ( errcode < DCERPC_FAULT_CODES[ mid ] ) {
                max = mid - 1;
            }
            else {
                return DCERPC_FAULT_MESSAGES[ mid ];
            }
        }

        return "0x" + Hexdump.toHexString(errcode, 8);
    }

    private int error;


    DcerpcException ( int error ) {
        super(getMessageByDcerpcError(error));
        this.error = error;
    }


    /**
     * @param msg
     */
    public DcerpcException ( String msg ) {
        super(msg);
    }


    /**
     * @param msg
     * @param rootCause
     */
    public DcerpcException ( String msg, Throwable rootCause ) {
        super(msg, rootCause);
    }


    /**
     * 
     * @return the error code
     */
    public int getErrorCode () {
        return this.error;
    }


    /**
     * 
     * @return the root cause
     */
    @Deprecated
    public Throwable getRootCause () {
        return getCause();
    }

}
