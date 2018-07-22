/* jcifs smb client library in Java
 * Copyright (C) 2000  "Michael B. Allen" <jcifs at samba dot org>
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

package jcifs.smb;


import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import jcifs.CIFSException;
import jcifs.util.Hexdump;


/**
 * There are hundreds of error codes that may be returned by a CIFS
 * server. Rather than represent each with it's own <code>Exception</code>
 * class, this class represents all of them. For many of the popular
 * error codes, constants and text messages like "The device is not ready"
 * are provided.
 * <p>
 * The jCIFS client maps DOS error codes to NTSTATUS codes. This means that
 * the user may receive a different error from a legacy server than that of
 * a newer variant such as Windows NT and above. If you should encounter
 * such a case, please report it to jcifs at samba dot org and we will
 * change the mapping.
 */

public class SmbException extends CIFSException implements NtStatus, DosError, WinError {

    /**
     * 
     */
    private static final long serialVersionUID = 484863569441792249L;
    
    // to replace a bunch of one-off binary searches
    private static final Map<Integer, String> errorCodeMessages;
    private static final Map<Integer, String> winErrorCodeMessages;
    private static final Map<Integer, Integer> dosErrorCodeStatuses;

    static {
        Map<Integer, String> errorCodeMessagesTmp = new HashMap<>();
        for (int i = 0; i < NT_STATUS_CODES.length; i++) {
            errorCodeMessagesTmp.put(NT_STATUS_CODES[i], NT_STATUS_MESSAGES[i]);
        }

        Map<Integer, Integer> dosErrorCodeStatusesTmp = new HashMap<>();
        for (int i = 0; i < DOS_ERROR_CODES.length; i++) {
            dosErrorCodeStatusesTmp.put(DOS_ERROR_CODES[i][0], DOS_ERROR_CODES[i][1]);
            int mappedNtCode = DOS_ERROR_CODES[i][1];
            String mappedNtMessage = errorCodeMessagesTmp.get(mappedNtCode);
            if (mappedNtMessage != null) {
                errorCodeMessagesTmp.put(DOS_ERROR_CODES[i][0], mappedNtMessage);
            }
        }
        
        // for backward compatibility since this is was different message in the NtStatus.NT_STATUS_CODES than returned
        // by getMessageByCode
        errorCodeMessagesTmp.put(0, "NT_STATUS_SUCCESS");

        errorCodeMessages = Collections.unmodifiableMap(errorCodeMessagesTmp);
        dosErrorCodeStatuses = Collections.unmodifiableMap(dosErrorCodeStatusesTmp);

        Map<Integer, String> winErrorCodeMessagesTmp = new HashMap<>();
        for (int i = 0; i < WINERR_CODES.length; i++) {
            winErrorCodeMessagesTmp.put(WINERR_CODES[i], WINERR_MESSAGES[i]);
        }

        winErrorCodeMessages = Collections.unmodifiableMap(winErrorCodeMessagesTmp);

    }





    /**
     * 
     * @param errcode
     * @return message for NT STATUS code
     * @internal
     */
    public static String getMessageByCode ( int errcode ) {
        String message = errorCodeMessages.get(errcode);
        if (message == null) {
            message =  "0x" + Hexdump.toHexString(errcode, 8);
        }
        return message;
    }


    static int getStatusByCode ( int errcode ) {
        int statusCode;
        if ( ( errcode & 0xC0000000 ) != 0 ) {
            statusCode = errcode;
        } else if (dosErrorCodeStatuses.containsKey(errcode)) {
            statusCode = dosErrorCodeStatuses.get(errcode);
        } else {
            statusCode = NT_STATUS_UNSUCCESSFUL;
        }
        return statusCode;
    }


    static String getMessageByWinerrCode ( int errcode ) {
        String message = winErrorCodeMessages.get(errcode);
        if (message == null) {
            message = "W" + Hexdump.toHexString(errcode, 8);
        }
        return message;
    }

    private int status;


    /**
     * 
     */
    public SmbException () {}


    /**
     * 
     * @param errcode
     * @param rootCause
     */
    public SmbException ( int errcode, Throwable rootCause ) {
        super(getMessageByCode(errcode), rootCause);
        this.status = getStatusByCode(errcode);
    }


    /**
     * 
     * @param msg
     */
    public SmbException ( String msg ) {
        super(msg);
        this.status = NT_STATUS_UNSUCCESSFUL;
    }


    /**
     * 
     * @param msg
     * @param rootCause
     */
    public SmbException ( String msg, Throwable rootCause ) {
        super(msg, rootCause);
        this.status = NT_STATUS_UNSUCCESSFUL;
    }


    /**
     * 
     * @param errcode
     * @param winerr
     */
    public SmbException ( int errcode, boolean winerr ) {
        super(winerr ? getMessageByWinerrCode(errcode) : getMessageByCode(errcode));
        this.status = winerr ? errcode : getStatusByCode(errcode);
    }


    /**
     * 
     * @return status code
     */
    public int getNtStatus () {
        return this.status;
    }


    /**
     * 
     * @return cause
     */
    @Deprecated
    public Throwable getRootCause () {
        return this.getCause();
    }


    /**
     * @param e
     * @return a CIFS exception wrapped in an SmbException
     */
    static SmbException wrap ( CIFSException e ) {
        if ( e instanceof SmbException ) {
            return (SmbException) e;
        }
        return new SmbException(e.getMessage(), e);
    }

}
